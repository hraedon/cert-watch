"""Tests for the publication identifier gate (``scripts/check_committed_identifiers.py``).

The gate is the mechanical guard that stops work-domain identifiers reaching a
published remote. It had no tests at all: ~550 lines whose *only* failure mode in
production is silence. A gate that stops matching still exits 0, and exit 0 is
indistinguishable from a clean tree -- so every rule below is asserted in both
directions (a tree that must fail, and a tree that must pass), never just "no
violations found".

The script is not importable as a package module (``scripts/`` is not a package),
so it is loaded from its path. That is deliberate: the tests exercise the same
file CI runs, not a copy.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_committed_identifiers.py"
_WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/identifier-gate.yml"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ad_steward_identifier_gate", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before executing: ``@dataclass`` resolves its own module out of
    # ``sys.modules`` to evaluate annotations, and an unregistered module makes
    # that lookup return None mid-decoration.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()

# The guarded-dir set is deliberately repo-specific: it names THIS repo's
# gitignored data directories, and a repo whose charter differs (guarding
# evidence/staging/local rather than samples/) is a supported configuration, not
# a deviation. The CLI-level tests below therefore ask the module what it guards
# instead of hardcoding "samples" -- otherwise this file tests one repo's
# spelling of the rule rather than the rule, and silently passes vacuously
# wherever the spelling differs.
GUARDED = sorted(gate._GUARDED_DIRS)[0]


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway git repo, with the CWD moved into it.

    The gate resolves its tree via ``git ls-files`` and its publication
    declaration via ``git rev-parse --show-toplevel``. Without a real repo the
    tests would silently read *ad-steward's own* tree and publication.toml --
    which is exactly the "aimed at the wrong target" failure the gate is meant to
    prevent, reproduced in the test suite.
    """
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
    monkeypatch.chdir(root)
    return root


def _track(root: Path, relpath: str, content: str | bytes) -> Path:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-f", "--", relpath], cwd=root, check=True)
    return path


def _commit(root: Path, message: str) -> str:
    subprocess.run(["git", "commit", "-q", "--no-verify", "-m", message], cwd=root, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _staged_blob(root: Path, relpath: str) -> str:
    """The stage-0 index content for *relpath* -- the bytes a commit would record."""
    return subprocess.run(
        ["git", "show", f":0:{relpath}"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout


def _declare(root: Path, visibility: str) -> None:
    (root / "publication.toml").write_text(
        f'[publication]\nremote_owner = "someone"\nvisibility = "{visibility}"\n',
        encoding="utf-8",
    )


# --------------------------------------------------------------------------
# parse_identifier_set
# --------------------------------------------------------------------------


def test_parses_whitespace_separated_secret_form() -> None:
    assert gate.parse_identifier_set("alpha beta gamma") == frozenset(
        {"alpha", "beta", "gamma"}
    )


def test_parses_one_entry_per_line() -> None:
    assert gate.parse_identifier_set("alpha\nbeta\n") == frozenset({"alpha", "beta"})


def test_strips_full_line_and_trailing_comments() -> None:
    raw = "# a full-line comment about servers\nalpha  # trailing note\nbeta\n"
    parsed = gate.parse_identifier_set(raw)
    assert parsed == frozenset({"alpha", "beta"})
    # The comment words must not become forbidden tokens -- otherwise documenting
    # the denylist would start failing the gate on innocent prose.
    assert "comment" not in parsed
    assert "servers" not in parsed


def test_keeps_quoted_multi_word_entry_whole() -> None:
    """The blind spot that hid a two-word name in sixteen repos.

    Unquoted, the halves are separate short tokens and the length filter drops
    them; quoted, the phrase survives as one entry.
    """
    assert gate.parse_identifier_set('"two words"') == frozenset({"two words"})
    # Unquoted, the same text is two independent tokens: the phrase cannot be
    # expressed at all, and any half below the length floor vanishes silently.
    unquoted = gate.parse_identifier_set("two words")
    assert "two words" not in unquoted
    assert unquoted == frozenset({"words"})
    # Both halves short: the entry disappears completely, matching nothing.
    assert gate.parse_identifier_set("ab cd") == frozenset()
    assert gate.parse_identifier_set('"ab cd"') == frozenset({"ab cd"})


def test_normalizes_case_and_internal_whitespace() -> None:
    assert gate.parse_identifier_set('"Two   Words"') == frozenset({"two words"})


def test_drops_tokens_below_the_minimum_length() -> None:
    short = "x" * (gate.MIN_IDENTIFIER_LENGTH - 1)
    long = "y" * gate.MIN_IDENTIFIER_LENGTH
    assert gate.parse_identifier_set(f"{short} {long}") == frozenset({long})


def test_unbalanced_quote_raises_rather_than_degrading() -> None:
    """A denylist we cannot parse must fail loudly, not silently shrink.

    Degrading to a partial token set is the dangerous outcome: the gate would run,
    report nothing, and exit 0 while scanning for fewer identifiers than declared.
    """
    with pytest.raises(ValueError):
        gate.parse_identifier_set('"unterminated')


def test_unbalanced_quote_makes_the_cli_exit_one(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", '"unterminated')
    assert gate.main([]) == 1


# --------------------------------------------------------------------------
# scan_text
# --------------------------------------------------------------------------


def test_match_is_case_insensitive() -> None:
    found = list(gate.scan_text("The WIDGETCORP server", frozenset({"widgetcorp"})))
    assert [v.identifier for v in found] == ["widgetcorp"]


def test_match_counts_substring_occurrences_inside_longer_tokens() -> None:
    """Real identifiers legitimately appear inside longer tokens."""
    found = list(gate.scan_text("host-widgetcorp-01.example", frozenset({"widgetcorp"})))
    assert len(found) == 1


def test_reports_every_occurrence_on_a_line() -> None:
    found = list(gate.scan_text("widgetcorp and widgetcorp", frozenset({"widgetcorp"})))
    assert len(found) == 2


def test_reports_the_correct_line_number() -> None:
    text = "clean\nclean\nwidgetcorp here\n"
    (violation,) = list(gate.scan_text(text, frozenset({"widgetcorp"})))
    assert violation.line_number == 3
    assert violation.line == "widgetcorp here"


def test_clean_text_yields_nothing() -> None:
    assert list(gate.scan_text("nothing to see\n", frozenset({"widgetcorp"}))) == []


def test_empty_identifier_set_yields_nothing() -> None:
    assert list(gate.scan_text("widgetcorp", frozenset())) == []


@pytest.mark.parametrize(
    "spelling",
    ["two words", "two-words", "two_words", "two.words", "two   words"],
)
def test_phrase_matches_every_separator_spelling(spelling: str) -> None:
    """One denylist entry must cover every way prose spells the phrase."""
    found = list(gate.scan_text(f"the {spelling} estate", frozenset({"two words"})))
    assert len(found) == 1, f"{spelling!r} escaped the phrase pattern"


def test_phrase_matches_across_a_line_break() -> None:
    """Wrapped prose is the case a line-by-line scanner cannot see."""
    text = "a sentence mentioning two\nwords in passing\n"
    (violation,) = list(gate.scan_text(text, frozenset({"two words"})))
    assert violation.line_number == 1


def test_phrase_does_not_match_across_an_unrelated_word() -> None:
    assert list(gate.scan_text("two other words", frozenset({"two words"}))) == []


def test_phrase_matching_is_case_insensitive() -> None:
    """Prose capitalises. A phrase entry must survive title case.

    Single-word matching lowercases the line; phrase matching goes through a
    separate compiled pattern, so the two can drift apart in exactly this way.
    """
    assert len(list(gate.scan_text("The Two Words estate", frozenset({"two words"})))) == 1


def test_phrase_metacharacters_are_escaped_literally() -> None:
    """A denylist entry is data, not a regex.

    ``acme (uk)`` unescaped compiles to ``acme[sep]+(uk)`` -- a capturing group
    that matches the *unrelated* string "acme uk" while missing the literal name
    it was written to catch. Both directions are asserted, because getting this
    wrong swaps which strings the gate sees rather than merely losing matches.

    Note this exercises the phrase path specifically: a single-word entry is
    matched with ``str.find`` and never reaches the regex at all.
    """
    entry = frozenset({"acme (uk)"})
    assert len(list(gate.scan_text("the acme (uk) estate", entry))) == 1
    assert list(gate.scan_text("the acme uk estate", entry)) == []


# --------------------------------------------------------------------------
# scan_files
# --------------------------------------------------------------------------


def test_scans_a_plain_utf8_file_and_records_the_path(tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("widgetcorp\n", encoding="utf-8")
    (violation,) = gate.scan_files(frozenset({"widgetcorp"}), [target])
    assert violation.path == target


@pytest.mark.parametrize(
    ("encoding", "bom", "has_nulls"),
    [
        ("utf-16-le", b"\xff\xfe", True),
        ("utf-16-be", b"\xfe\xff", True),
        ("utf-8-sig", b"", False),  # the codec emits its own BOM
    ],
)
def test_bom_marked_text_is_decoded_not_dismissed_as_binary(
    tmp_path: Path, encoding: str, bom: bytes, has_nulls: bool
) -> None:
    """UTF-16 is common in Windows tooling output and is full of null bytes.

    The null-byte heuristic alone would classify it as binary and skip it --
    a whole file class silently exempt from the gate. The explicit-endian codecs
    emit no BOM of their own, so the marker is written deliberately, which is how
    the Windows tools producing these files write them.
    """
    target = tmp_path / "export.txt"
    target.write_bytes(bom + "widgetcorp\n".encode(encoding))
    raw = target.read_bytes()
    assert gate._sniff_encoding(raw) == encoding
    assert (b"\x00" in raw) is has_nulls
    assert gate._is_binary(raw) is False, "a BOM must override the null-byte heuristic"
    assert len(gate.scan_files(frozenset({"widgetcorp"}), [target])) == 1


def test_utf16_bom_does_not_leak_into_the_reported_line(tmp_path: Path) -> None:
    """An explicit-endian UTF-16 decode leaves U+FEFF at the start of line 1.

    It hides nothing -- matching is substring-based, so the identifier is found
    either way -- but a report that prints an invisible character before the
    offending text is one people mistrust, and the two scan modes must agree.
    """
    target = tmp_path / "export.txt"
    target.write_bytes(b"\xff\xfe" + "widgetcorp is here\n".encode("utf-16-le"))
    (violation,) = gate.scan_files(frozenset({"widgetcorp"}), [target])
    assert violation.line == "widgetcorp is here"
    assert not violation.line.startswith("\ufeff")


def test_staged_utf16_bom_is_stripped_too(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The staged path must strip it as well, or the modes disagree."""
    _track(repo, "export.txt", b"\xff\xfe" + "widgetcorp is here\n".encode("utf-16-le"))
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    violations = gate.scan_staged_blobs(
        frozenset({"widgetcorp"}), [Path("export.txt")]
    )
    assert violations and violations[0].line == "widgetcorp is here"


def test_genuine_binary_is_skipped(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00\x01\x02widgetcorp")
    assert gate.scan_files(frozenset({"widgetcorp"}), [target]) == []


def test_symlink_target_string_is_scanned_without_following_the_link(
    tmp_path: Path,
) -> None:
    """A tracked symlink's blob content IS its target path.

    Following it either leaves the repo or fails on a broken link; the target
    string itself can carry the identifier, so it is scanned in place.
    """
    link = tmp_path / "link"
    link.symlink_to("/srv/widgetcorp/data")
    (violation,) = gate.scan_files(frozenset({"widgetcorp"}), [link])
    assert violation.path == link
    assert violation.line == "/srv/widgetcorp/data"


def test_broken_symlink_does_not_count_as_unreadable(tmp_path: Path) -> None:
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "does-not-exist")
    unreadable: list[Path] = []
    assert gate.scan_files(frozenset({"widgetcorp"}), [link], unreadable=unreadable) == []
    assert unreadable == []


def test_unreadable_file_is_collected_rather_than_silently_skipped(
    tmp_path: Path,
) -> None:
    """Skipping an unreadable file is the fails-open case the gate exists to stop."""
    target = tmp_path / "secret.md"
    target.write_text("widgetcorp\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        if os.access(target, os.R_OK):  # root ignores the mode bits
            pytest.skip("cannot make a file unreadable as this user")
        unreadable: list[Path] = []
        violations = gate.scan_files(frozenset({"widgetcorp"}), [target], unreadable=unreadable)
        assert violations == []
        assert unreadable == [target]
    finally:
        target.chmod(0o644)


def test_scan_files_returns_a_list_not_a_tuple(tmp_path: Path) -> None:
    """Fleet-wide contract: this script is copied into every repo in the estate
    and several of them assert on ``scan_files``' return type directly. Returning
    a tuple once broke seven test suites at the same time.
    """
    assert isinstance(gate.scan_files(frozenset({"widgetcorp"}), []), list)


# --------------------------------------------------------------------------
# leaked_tracked_files (the always-on guard)
# --------------------------------------------------------------------------


def test_root_level_samples_file_is_flagged() -> None:
    leaked = gate.leaked_tracked_files([Path("samples/capture.json")], frozenset({"samples"}))
    assert leaked == [Path("samples/capture.json")]


def test_nested_samples_directory_is_not_a_false_positive() -> None:
    """``tests/samples/`` is a legitimate code directory, not the data dir."""
    nested = [Path("tests/samples/fixture.json")]
    assert gate.leaked_tracked_files(nested, frozenset({"samples"})) == []


@pytest.mark.parametrize(
    "name", ["notes.swp", "notes.swo", ".notes.md.swp", ".notes.md.swn"]
)
def test_editor_swap_files_are_never_tracked(name: str) -> None:
    """A swap file holds the BUFFER of the file being edited.

    A secret typed and not yet saved lives in there, so it is guarded regardless
    of denylist configuration. Vim's collision sequence (.swo, .swn, ... once
    .swp is taken) is why suffix matching alone is not enough.
    """
    assert gate.leaked_tracked_files([Path(name)], frozenset()) == [Path(name)]


def test_a_swap_file_deep_in_the_tree_is_still_caught() -> None:
    p = Path("src/deep/.thing.py.swp")
    assert gate.leaked_tracked_files([p], frozenset()) == [p]


@pytest.mark.parametrize("name", [".env", ".env.local", ".env.production"])
def test_root_level_env_files_are_never_tracked(name: str) -> None:
    assert gate.leaked_tracked_files([Path(name)], frozenset()) == [Path(name)]


def test_env_example_is_the_deliberately_tracked_template() -> None:
    assert gate.leaked_tracked_files([Path(".env.example")], frozenset()) == []


def test_a_nested_env_file_is_not_guarded() -> None:
    """Scoped to the ROOT, so a fixture like tests/fixtures/.env.broken stays possible."""
    assert gate.leaked_tracked_files([Path("tests/fixtures/.env.broken")], frozenset()) == []


def test_ordinary_dotfiles_are_not_guarded() -> None:
    """The rules must not swallow normal repo furniture."""
    ordinary = [Path(".gitignore"), Path(".editorconfig"), Path("env.py"), Path("a.swap")]
    assert gate.leaked_tracked_files(ordinary, frozenset()) == []


def test_guard_fires_through_the_cli_on_a_force_added_sample(repo: Path) -> None:
    """``.gitignore`` is advisory -- ``git add -f`` bypasses it. This is the catch."""
    _track(repo, f"{GUARDED}/capture.json", "{}\n")
    _commit(repo, "force-add a capture")
    assert gate.main([]) == 1


def test_cli_passes_a_tree_with_no_guarded_files(repo: Path) -> None:
    _track(repo, f"tests/{GUARDED}/fixture.json", "{}\n")
    _commit(repo, "add a legitimate nested fixture")
    assert gate.main([]) == 0


# --------------------------------------------------------------------------
# Unconfigured-denylist semantics: the silent-pass asymmetry
# --------------------------------------------------------------------------


def test_unset_secret_is_a_no_op_without_a_declaration(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repo that never opted into the publication system is not blocked."""
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert not (repo / "publication.toml").exists()
    assert gate.main([]) == 0


def test_unset_secret_is_a_no_op_for_a_private_repo(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(repo, "private-until-review")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    _commit(repo, "declare private")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main([]) == 0


def test_unset_secret_fails_closed_for_a_public_repo(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole point. On a public repo "skipping" and "clean" look identical,
    and a leak there is irreversible -- so an unconfigured gate must fail.
    """
    _declare(repo, "public")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    _commit(repo, "declare public")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main([]) == 1
    assert "silent pass" in capsys.readouterr().err


def test_public_repo_with_a_configured_gate_and_clean_tree_passes(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(repo, "public")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    _track(repo, "README.md", "nothing sensitive here\n")
    _commit(repo, "declare public")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main([]) == 0


def test_all_short_denylist_entries_fail_closed_for_a_public_repo(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A secret that parses to nothing is unconfigured by another name."""
    _declare(repo, "public")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    _commit(repo, "declare public")
    too_short = "x" * (gate.MIN_IDENTIFIER_LENGTH - 1)
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", too_short)
    assert gate.main([]) == 1


def test_unparseable_declaration_fails_rather_than_guessing(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Present-but-broken is not the same as absent.

    That repo *did* opt in, and guessing its visibility is exactly the coin-flip
    the declaration exists to remove.
    """
    (repo / "publication.toml").write_text("[publication\nnot = toml", encoding="utf-8")
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main([]) == 1


def test_declaration_without_a_publication_table_fails(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "publication.toml").write_text('[other]\nkey = "value"\n', encoding="utf-8")
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main([]) == 1


def test_configured_gate_catches_an_identifier_in_a_tracked_file(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "docs/notes.md", "the widgetcorp estate\n")
    _commit(repo, "add notes")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main([]) == 1


def test_redacted_ci_output_omits_identifier_and_source_line(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identifier = "private-widget-92831"
    source_line = f"endpoint = https://{identifier}.example.test"
    _track(repo, "src/settings.py", f"{source_line}\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", identifier)

    assert gate.main(["--redact-output"]) == 1

    err = capsys.readouterr().err
    assert "<path sha256:3ac2227be4f4>:1: denylist entry #1" in err  # src/settings.py
    assert identifier not in err
    assert source_line not in err


@pytest.mark.parametrize(
    "path",
    [
        "private-widget-92831/settings.py",
        "src/private-widget-92831-settings.py",
    ],
    ids=["directory-name", "filename"],
)
def test_redacted_ci_output_omits_identifier_from_path_components(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    path: str,
) -> None:
    identifier = "private-widget-92831"
    _track(repo, path, f"endpoint = https://{identifier}.example.test\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", identifier)

    assert gate.main(["--redact-output"]) == 1

    err = capsys.readouterr().err
    assert "<path sha256:" in err
    assert identifier not in err


def test_redacted_guard_report_omits_identifier_from_path(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identifier = "private-widget-92831"
    _track(repo, f"{GUARDED}/{identifier}/capture.json", "{}\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", identifier)

    assert gate.main(["--redact-output"]) == 1

    err = capsys.readouterr().err
    assert "<path sha256:" in err
    assert GUARDED not in err
    assert identifier not in err


def test_redacted_unreadable_report_omits_identifier_from_path(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identifier = "private-widget-92831"
    path = Path("docs") / f"{identifier}.md"
    _track(repo, path.as_posix(), "clean content\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", identifier)

    def collect_as_unreadable(
        identifiers: frozenset[str],
        paths: list[Path],
        *,
        unreadable: list[Path],
    ) -> list[object]:
        assert identifiers == frozenset({identifier})
        assert path in paths
        unreadable.append(path)
        return []

    monkeypatch.setattr(gate, "scan_files", collect_as_unreadable)

    assert gate.main(["--redact-output"]) == 1

    err = capsys.readouterr().err
    assert "<path sha256:" in err
    assert "docs/" not in err
    assert identifier not in err


def test_print_report_requires_identifiers_when_redacting() -> None:
    violation = gate.Violation(
        identifier="private-widget-92831",
        path=Path("src/settings.py"),
        line_number=1,
        line="private-widget-92831",
    )

    with pytest.raises(gate.GateError, match="redacted reports require the identifier set"):
        gate.print_report([violation], redact_output=True)


def test_configured_gate_catches_a_quoted_phrase_in_a_tracked_file(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "docs/notes.md", "the two-words estate\n")
    _commit(repo, "add notes")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", '"two words"')
    assert gate.main([]) == 1


def test_unreadable_tracked_file_blocks_the_cli(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _track(repo, "docs/locked.md", "clean content\n")
    _commit(repo, "add a file")
    target.chmod(0o000)
    try:
        if os.access(target, os.R_OK):
            pytest.skip("cannot make a file unreadable as this user")
        monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
        assert gate.main([]) == 1
    finally:
        target.chmod(0o644)


# --------------------------------------------------------------------------
# Commit-message modes (the channel the content scan cannot see)
# --------------------------------------------------------------------------


def test_commit_message_file_with_an_identifier_is_rejected(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("redact widgetcorp from the docs\n", encoding="utf-8")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--message-file", str(msg)]) == 1


def test_clean_commit_message_file_passes(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("redact the customer name from the docs\n", encoding="utf-8")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--message-file", str(msg)]) == 0


def test_commit_message_comment_lines_are_ignored(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git strips ``#`` lines, so they are never published and must not block."""
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("a clean subject\n#\n# On branch widgetcorp-fix\n", encoding="utf-8")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--message-file", str(msg)]) == 0


def test_rev_range_scans_published_commit_messages(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented leak: the very commits that redacted an identifier from the
    files named it in their messages, and the tracked-tree scan cannot see that.
    """
    _track(repo, "README.md", "clean\n")
    base = _commit(repo, "a clean base commit")
    _track(repo, "README.md", "still clean\n")
    _commit(repo, "remove widgetcorp from the docs")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--rev-range", f"{base}..HEAD"]) == 1


def test_rev_range_passes_when_every_message_is_clean(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "README.md", "clean\n")
    base = _commit(repo, "a clean base commit")
    _track(repo, "README.md", "still clean\n")
    _commit(repo, "tidy the documentation")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--rev-range", f"{base}..HEAD"]) == 0


def test_rev_range_accepts_the_multi_argument_new_branch_form(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pre-push passes ``"<sha> --not --remotes=<name>"`` as one string for a
    branch with no upstream; it must be split, not treated as one opaque ref.

    Asserting only "exit 1" would be vacuous here: passing the whole string as a
    single ref makes *git itself* fail, which also exits 1. So the clean case must
    exit 0 (git ran and found nothing), and the dirty case must name a forbidden
    identifier rather than report that the gate could not complete.
    """
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")

    _track(repo, "README.md", "clean\n")
    _commit(repo, "a perfectly clean subject")
    assert gate.main(["--rev-range", "HEAD --not --remotes=origin"]) == 0
    assert "could not complete" not in capsys.readouterr().err

    _track(repo, "README.md", "still clean\n")
    _commit(repo, "mentions widgetcorp in the message")
    assert gate.main(["--rev-range", "HEAD --not --remotes=origin"]) == 1
    err = capsys.readouterr().err
    assert "Forbidden identifier in commit message" in err
    assert "could not complete" not in err


# --------------------------------------------------------------------------
# Staged mode (pre-commit hook)
# --------------------------------------------------------------------------


def test_staged_mode_scans_only_what_is_about_to_be_committed(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "docs/old.md", "the widgetcorp estate\n")
    _commit(repo, "a pre-existing file")
    _track(repo, "docs/new.md", "perfectly clean\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    # The committed file is dirty, but it is not staged: --staged must not fail.
    assert gate.main(["--staged"]) == 0
    # The whole-tree scan, which CI runs, still sees it.
    assert gate.main([]) == 1


def test_staged_mode_catches_a_rename_into_a_guarded_directory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--no-renames`` decomposes a rename into add+delete so the NEW path is
    visible to the always-on guard. Without it a file moved into ``samples/``
    would be reported only as a rename and slip past.
    """
    _track(repo, "capture.json", '{"host": "x"}\n')
    _commit(repo, "add a capture at the root")
    subprocess.run(["git", "mv", "capture.json", "moved.json"], cwd=repo, check=True)
    (repo / GUARDED).mkdir()
    dest = f"{GUARDED}/capture.json"
    subprocess.run(["git", "mv", "moved.json", dest], cwd=repo, check=True)
    subprocess.run(["git", "add", "-f", "--", dest], cwd=repo, check=True)
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main(["--staged"]) == 1


def test_staged_mode_judges_the_index_not_the_worktree(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bypass this scanner exists to close.

    A commit records the INDEX. Staging a forbidden identifier and then
    overwriting the working copy with clean bytes leaves an index blob that
    still carries it -- and a gate that reads the worktree sees only the clean
    bytes, passes, and lets the forbidden blob into history. The worktree
    content here is deliberately innocent: if this test ever passes by reading
    the file, it is reading the wrong thing.
    """
    _track(repo, "notes.md", "the widgetcorp estate\n")
    (repo / "notes.md").write_text("perfectly innocent text\n", encoding="utf-8")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")

    assert (repo / "notes.md").read_text() == "perfectly innocent text\n"
    assert "widgetcorp" in _staged_blob(repo, "notes.md")
    assert gate.main(["--staged"]) == 1


def test_staged_mode_ignores_unstaged_worktree_content(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inverse, which matters just as much.

    A clean index under a dirty worktree was blocked for content no commit was
    going to record. A gate that cries wolf on work in progress trains people to
    reach for --no-verify, which disables it entirely.
    """
    _track(repo, "notes.md", "perfectly innocent text\n")
    (repo / "notes.md").write_text("the widgetcorp estate\n", encoding="utf-8")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")

    assert gate.main(["--staged"]) == 0

    # The two modes read different things, and that is the whole point. The
    # default scan reads the CHECKED-OUT bytes, so it still sees the dirty
    # worktree and refuses. In CI the distinction is invisible because the
    # checkout is pristine and index, worktree and HEAD all agree -- which is
    # exactly why this divergence has to be pinned by a test rather than noticed.
    _commit(repo, "commit the clean index")
    assert gate.main([]) == 1


def test_staged_binary_blob_is_skipped(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binary handling must match scan_files, or the two modes disagree."""
    _track(repo, "blob.bin", b"\x00\x01\x02widgetcorp")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--staged"]) == 0


def test_staged_utf16_blob_is_decoded(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "export.txt", b"\xff\xfe" + "widgetcorp\n".encode("utf-16-le"))
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--staged"]) == 1


def test_scan_staged_blobs_returns_a_list(repo: Path) -> None:
    """Same fleet-wide return-type contract as scan_files."""
    assert isinstance(gate.scan_staged_blobs(frozenset({"widgetcorp"}), []), list)


# --------------------------------------------------------------------------
# Failing clean: a gate that cannot judge must not look like a pass
# --------------------------------------------------------------------------


def test_git_failure_becomes_a_clean_exit_one_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Outside a repo, ``git ls-files`` fails. A publication gate must report that
    as a blocked publication, not a CalledProcessError stack trace that reads as
    broken infrastructure.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main([]) == 1
    assert "identifier gate could not complete" in capsys.readouterr().err


def test_run_git_raises_gate_error_when_git_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("no git here")

    monkeypatch.setattr(gate.subprocess, "run", _boom)
    with pytest.raises(gate.GateError):
        gate._run_git(["git", "status"])


def test_gate_error_message_names_the_failing_command() -> None:
    with pytest.raises(gate.GateError) as excinfo:
        gate._run_git([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert "exit 3" in str(excinfo.value)


# --------------------------------------------------------------------------
# Staged-mode publication declaration: judged from the index, not the worktree
# --------------------------------------------------------------------------


def test_staged_mode_ignores_a_worktree_only_public_declaration(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A declaration staged into the NEXT commit is not yet the repo's
    declaration; the gate judges the index it is about to commit."""
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    # public declaration exists only as an UNSTAGED worktree file
    _declare(repo, "public")
    _track(repo, "new-file.md", "content\n")  # stage something else
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main(["--staged"]) == 0


def test_staged_mode_reads_a_staged_public_declaration(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _track(repo, "README.md", "hello\n")
    _commit(repo, "init")
    _declare(repo, "public")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main(["--staged"]) == 1


def test_staged_mode_follows_the_committed_declaration_over_worktree_edit(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declaration committed as public, then edited to private in the worktree
    but NOT staged: the commit being gated still carries public, so the gate
    stays failed-closed."""
    _declare(repo, "public")
    _track(repo, "publication.toml", (repo / "publication.toml").read_text())
    _commit(repo, "declare public")
    _declare(repo, "private-until-review")  # worktree only
    _track(repo, "unrelated.md", "content\n")
    monkeypatch.delenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", raising=False)
    assert gate.main(["--staged"]) == 1


# --------------------------------------------------------------------------
# Staged type-changes are scanned (diff-filter ACMT)
# --------------------------------------------------------------------------


def test_staged_type_change_file_to_symlink_is_scanned(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tracked file re-staged as a symlink whose TARGET names a forbidden
    identifier is a type-change (T), which --diff-filter=ACM missed."""
    _track(repo, "pointer", "plain text\n")
    _commit(repo, "add plain file")
    (repo / "pointer").unlink()
    (repo / "pointer").symlink_to("/srv/widgetcorp/data")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    assert "pointer" in [p.as_posix() for p in gate.collect_staged_paths()]
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--staged"]) == 1


# --------------------------------------------------------------------------
# scan_staged_blobs fail-closed default
# --------------------------------------------------------------------------


def test_unreadable_staged_blob_raises_when_no_collector_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gate, "_read_staged_blob",
        lambda *a, **kw: (_ for _ in ()).throw(gate.GateError("simulated read failure")),
    )
    import pytest as _pytest
    with _pytest.raises(gate.GateError, match="could not be read"):
        gate.scan_staged_blobs(gate.parse_identifier_set("widgetcorp"), [Path("x")])
    collected: list[Path] = []
    out = gate.scan_staged_blobs(
        gate.parse_identifier_set("widgetcorp"), [Path("x")], unreadable=collected,
    )
    assert out == []
    assert collected == [Path("x")]


# --------------------------------------------------------------------------
# --tree mode (unpacked-tree scanning)
# --------------------------------------------------------------------------


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_tree_mode_scans_a_tree_outside_any_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _write_tree(tmp_path / "pr-tree", {"src/app.py": "host = widgetcorp\n"})
    _declare(tmp_path, "private-until-review")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--tree", str(tree)]) == 1


def test_tree_mode_clean_tree_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _write_tree(tmp_path / "pr-tree", {"src/app.py": "print('hi')\n"})
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--tree", str(tree)]) == 0


def test_tree_mode_never_descends_into_dot_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _write_tree(
        tmp_path / "pr-tree",
        {".git/config": "widgetcorp-internal-host\n", "src/app.py": "ok\n"},
    )
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp-internal-host")
    assert gate.main(["--tree", str(tree)]) == 0


def test_tree_mode_guard_guard_paths_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The always-on guards (guarded data dir, root .env, swap files) apply to a
    scanned tree exactly as they do to a tracked tree."""
    tree = _write_tree(tmp_path / "pr-tree", {".env": "PASSWORD=hunter2\n"})
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", "widgetcorp")
    assert gate.main(["--tree", str(tree)]) == 1


def test_tree_mode_combines_with_neither_staged_nor_range(
    tmp_path: Path,
) -> None:
    import pytest as _pytest
    tree = _write_tree(tmp_path / "pr-tree", {"a.txt": "x\n"})
    with _pytest.raises(SystemExit):
        gate.main(["--tree", str(tree), "--staged"])


# --------------------------------------------------------------------------
# GitHub Actions trust-boundary routing
# --------------------------------------------------------------------------


def _identifier_gate_workflow() -> dict[str, object]:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


_IF_TOKEN = re.compile(
    r"\s*(?:(?P<op>==|!=|&&|\|\||\(|\))|"
    r"(?P<string>'[^']*')|(?P<name>[A-Za-z_][A-Za-z0-9_.]*))"
)


def _evaluate_workflow_if(expression: str, context: dict[str, object]) -> bool:
    """Evaluate the small GitHub-expression subset used by this workflow.

    The parser intentionally rejects everything outside identifiers, single-quoted
    strings, null, comparisons, boolean operators, and parentheses. A permissive
    test evaluator would turn new workflow syntax into an untested branch.
    """
    tokens: list[str] = []
    offset = 0
    while offset < len(expression):
        match = _IF_TOKEN.match(expression, offset)
        if match is None:
            raise AssertionError(
                f"unsupported workflow if syntax at {expression[offset:]!r}"
            )
        token = next(group for group in match.groups() if group is not None)
        tokens.append(token)
        offset = match.end()

    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def consume(expected: str | None = None) -> str:
        nonlocal position
        token = peek()
        if token is None or (expected is not None and token != expected):
            raise AssertionError(f"expected {expected!r}, got {token!r} in {expression!r}")
        position += 1
        return token

    def resolve(name: str) -> object:
        if name == "null":
            return None
        value: object = context
        for part in name.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def primary() -> object:
        token = peek()
        if token == "(":
            consume("(")
            value = disjunction()
            consume(")")
            return value
        if token is None:
            raise AssertionError(f"unexpected end of workflow if expression {expression!r}")
        consume()
        if token.startswith("'"):
            return token[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", token):
            return resolve(token)
        raise AssertionError(f"unsupported workflow if token {token!r}")

    def comparison() -> bool:
        left = primary()
        operator = peek()
        if operator not in {"==", "!="}:
            if isinstance(left, bool):
                return left
            raise AssertionError(
                f"workflow if operand lacks a supported comparison in {expression!r}"
            )
        consume()
        right = primary()
        return left == right if operator == "==" else left != right

    def conjunction() -> bool:
        value = comparison()
        while peek() == "&&":
            consume("&&")
            value = comparison() and value
        return value

    def disjunction() -> bool:
        value = conjunction()
        while peek() == "||":
            consume("||")
            value = conjunction() or value
        return value

    result = disjunction()
    if position != len(tokens):
        raise AssertionError(f"unsupported trailing workflow if tokens: {tokens[position:]}")
    return result


def _workflow_context(event: str, head_repository: str | None) -> dict[str, object]:
    return {
        "github": {
            "event_name": event,
            "repository": "owner/cert-watch",
            "event": {
                "pull_request": {
                    "head": {
                        "repo": None if head_repository is None else {"full_name": head_repository}
                    }
                }
            },
        }
    }


def test_workflow_push_with_tracked_pr_tree_scans_full_tree(repo: Path) -> None:
    """A tracked ``pr-tree/`` directory cannot switch a push to subtree mode."""
    workflow = _identifier_gate_workflow()
    job = workflow["jobs"]["identifier-gate"]
    scan_step = next(
        step
        for step in job["steps"]
        if step.get("name") == "Check for committed work-domain identifiers"
    )
    command = scan_step["run"]

    identifier = "private-push-value-92831"
    _track(repo, "scripts/check_committed_identifiers.py", _SCRIPT.read_bytes())
    _track(repo, "pr-tree/README.md", "clean subtree\n")
    _track(repo, "outside-pr-tree.txt", f"contains {identifier}\n")
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "push"
    env["CERT_WATCH_FORBIDDEN_IDENTIFIERS"] = identifier

    result = subprocess.run(
        ["bash", "-c", command],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "<path sha256:eb973e9e39b9>:1: denylist entry #1" in result.stderr  # outside-pr-tree.txt
    assert identifier not in result.stderr


def test_workflow_fork_pr_fails_closed_without_secret_or_checkout() -> None:
    workflow = _identifier_gate_workflow()
    job = workflow["jobs"]["identifier-gate"]
    cases = [
        ("push", None, {"checkout", "setup", "scan"}),
        ("pull_request", "owner/cert-watch", {"checkout", "setup", "scan"}),
        ("pull_request", "contributor/fork", set()),
        ("pull_request_target", "owner/cert-watch", set()),
        ("pull_request_target", "contributor/fork", {"reject"}),
        ("pull_request_target", None, {"reject"}),  # deleted fork: fail closed
    ]
    def step_name(step: dict[str, object]) -> str:
        name = step.get("name")
        if name == "Reject fork pull request without exposing the denylist":
            return "reject"
        if name == "Set up Python":
            return "setup"
        if name == "Check for committed work-domain identifiers":
            return "scan"
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("actions/checkout@"):
            return "checkout"
        raise AssertionError(f"unrecognized identifier-gate step: {step!r}")

    for event, head_repository, expected in cases:
        context = _workflow_context(event, head_repository)
        if not _evaluate_workflow_if(job["if"], context):
            actual: set[str] = set()
        else:
            actual = set()
            for step in job["steps"]:
                condition = step.get("if")
                if condition is None or _evaluate_workflow_if(condition, context):
                    actual.add(step_name(step))
        assert actual == expected, (event, head_repository)

    scan_step = next(step for step in job["steps"] if step.get("name", "").startswith("Check"))
    assert scan_step["env"] == {
        "CERT_WATCH_FORBIDDEN_IDENTIFIERS": "${{ secrets.CERT_WATCH_FORBIDDEN_IDENTIFIERS }}"
    }

    fork_step = next(step for step in job["steps"] if step.get("name", "").startswith("Reject"))
    result = subprocess.run(
        ["bash", "-c", fork_step["run"]], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert "maintainer must re-push" in result.stdout
    fork_serialized = yaml.safe_dump(fork_step)
    assert "CERT_WATCH_FORBIDDEN_IDENTIFIERS" not in fork_serialized
    assert "actions/checkout" not in fork_serialized


# --------------------------------------------------------------------------
# Vim collision-plane semantics: deliberate, and pinned
# --------------------------------------------------------------------------


def test_vim_collision_plane_does_not_catch_plain_extension_files() -> None:
    """``logo.svg`` is a normal file; only DOT-starting names with the vim
    collision suffix (e.g. ``.logo.svg`` — vim's swap for ``logo.sv``) are
    treated as swap files. A tracked legitimate dotfile with such a suffix is
    rejected by design: the false-positive window is narrower than the leak."""
    assert gate.leaked_tracked_files([Path("docs/logo.svg")], gate._GUARDED_DIRS) == []
    assert gate.leaked_tracked_files([Path(".logo.svg")], gate._GUARDED_DIRS) == [
        Path(".logo.svg"),
    ]


# --------------------------------------------------------------------------
# Hooks no longer short-circuit before invoking the gate
# --------------------------------------------------------------------------


_HOOKS = Path(__file__).resolve().parents[1] / "githooks"


def _run_hook_env(home: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "CERT_WATCH_FORBIDDEN_IDENTIFIERS"
    }
    env["HOME"] = str(home)
    return env


def _run_hook(
    repo: Path, hook: str, home: Path, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run a repo's hook with the denylist truly absent: no env var, no
    per-repo file, and a HOME that cannot contain the shared one."""
    return subprocess.run(
        ["bash", str(repo / "githooks" / hook), *args],
        cwd=repo,
        env=_run_hook_env(home),
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def hooked_repo(repo: Path) -> Path:
    """The throwaway repo, with this repo's gate script and hooks installed."""
    (repo / "scripts").mkdir()
    shutil.copy2(_SCRIPT, repo / "scripts" / _SCRIPT.name)
    (repo / "githooks").mkdir()
    for hook in ("pre-commit", "commit-msg", "pre-push"):
        shutil.copy2(_HOOKS / hook, repo / "githooks" / hook)
    return repo


def test_pre_commit_hook_fails_closed_for_a_public_repo_without_a_denylist(
    hooked_repo: Path, tmp_path: Path
) -> None:
    _declare(hooked_repo, "public")
    _track(hooked_repo, "publication.toml", (hooked_repo / "publication.toml").read_text())
    _commit(hooked_repo, "declare public")
    _track(hooked_repo, "new-file.md", "content\n")
    result = _run_hook(hooked_repo, "pre-commit", tmp_path / "home")
    assert result.returncode == 1
    assert "INACTIVE" not in result.stderr


def test_pre_commit_hook_swap_and_env_guards_fire_without_a_denylist(
    hooked_repo: Path, tmp_path: Path
) -> None:
    """The always-on guards must run even when the gate is unconfigured —
    previously the hook exited 0 before the script could see the force-add."""
    _track(hooked_repo, "README.md", "x\n")
    _commit(hooked_repo, "init")
    _track(hooked_repo, ".env", "PASSWORD=hunter2\n")
    result = _run_hook(hooked_repo, "pre-commit", tmp_path / "home")
    assert result.returncode == 1
    assert ".env" in result.stderr


def test_pre_commit_hook_private_repo_without_a_denylist_passes(
    hooked_repo: Path, tmp_path: Path
) -> None:
    _track(hooked_repo, "README.md", "nothing sensitive\n")
    result = _run_hook(hooked_repo, "pre-commit", tmp_path / "home")
    assert result.returncode == 0


def test_commit_msg_hook_asks_the_gate_instead_of_short_circuiting(
    hooked_repo: Path, tmp_path: Path
) -> None:
    """Without the denylist the script decides: this repo declares nothing, so
    commit-msg passes; a forbidden message WITH the denylist must still fail
    through the same hook path."""
    _track(hooked_repo, "README.md", "x\n")
    message = hooked_repo / ".git" / "COMMIT_EDITMSG"
    message.write_text("add the widgetcorp endpoint\n", encoding="utf-8")
    result = _run_hook(hooked_repo, "commit-msg", tmp_path / "home", str(message))
    assert result.returncode == 0

    env_dir = hooked_repo / ".identifiers-denylist.local"
    env_dir.write_text("widgetcorp\n", encoding="utf-8")
    result = _run_hook(hooked_repo, "commit-msg", tmp_path / "home", str(message))
    assert result.returncode == 1


def _pre_push_stdin(sha: str) -> str:
    zero = "0" * 40
    return f"refs/heads/main {sha} refs/heads/main {zero}\n"


def _prepare_pre_push_repo(hooked_repo: Path) -> str:
    """A repo ready for a pre-push run: publication declaration, origin remote,
    and the plumbing script installed. Returns the HEAD sha."""
    shutil.copy2(
        _SCRIPT.parent / "check_publication_plumbing.py",
        hooked_repo / "scripts" / "check_publication_plumbing.py",
    )
    (hooked_repo / "publication.toml").write_text(
        '[publication]\nremote_owner = "someone"\n'
        'author_email = "t@example.invalid"\nvisibility = "public"\n',
        encoding="utf-8",
    )
    _track(hooked_repo, "publication.toml", (hooked_repo / "publication.toml").read_text())
    _track(hooked_repo, "README.md", "hello\n")
    _commit(hooked_repo, "init publication")
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/someone/repo.git"],
        cwd=hooked_repo, check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=hooked_repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def test_pre_push_hook_scans_commit_messages_without_short_circuit(
    hooked_repo: Path, tmp_path: Path
) -> None:
    """The pre-push message scan must run even when the denylist resolves only
    from a local file -- previously the hook skipped it entirely."""
    _prepare_pre_push_repo(hooked_repo)
    _track(hooked_repo, "feature.md", "new feature\n")
    _commit(hooked_repo, "wire up the widgetcorp endpoint")
    (hooked_repo / ".identifiers-denylist.local").write_text(
        "widgetcorp\n", encoding="utf-8",
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=hooked_repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()

    # Feed stdin the ref update git provides at push time...
    result = subprocess.run(
        ["bash", str(hooked_repo / "githooks" / "pre-push"),
         "origin", "https://github.com/someone/repo.git"],
        cwd=hooked_repo,
        env=_run_hook_env(tmp_path / "home"),
        input=_pre_push_stdin(head),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "widgetcorp" in result.stderr
    assert "commit message" in result.stderr


def test_pre_push_hook_fails_closed_for_public_repo_without_a_denylist(
    hooked_repo: Path, tmp_path: Path
) -> None:
    """visibility=\"public\" + no denylist = the gate may not pass. pre-push must
    surface that, not skip the scan and publish anyway."""
    head = _prepare_pre_push_repo(hooked_repo)
    result = subprocess.run(
        ["bash", str(hooked_repo / "githooks" / "pre-push"),
         "origin", "https://github.com/someone/repo.git"],
        cwd=hooked_repo,
        env=_run_hook_env(tmp_path / "home"),
        input=_pre_push_stdin(head),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "IDENTIFIERS" in result.stderr


@pytest.mark.parametrize(
    ("identifier", "path"),
    [
        # A phrase split across path components: no per-component match sees it.
        ("two words", "two/words.md"),
        # The same identifier in a different Unicode normalisation form.
        ("priva\u0301te-widget-92831", "priv\u00e1te-widget-92831/f.txt"),
    ],
)
def test_redacted_report_never_prints_a_path(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    identifier: str,
    path: str,
) -> None:
    _track(repo, path, "the two words estate\n" + identifier + "\n")
    monkeypatch.setenv("CERT_WATCH_FORBIDDEN_IDENTIFIERS", identifier)

    gate.main(["--redact-output"])

    err = capsys.readouterr().err
    assert Path(path).parts[0] not in err
    assert Path(path).name not in err


def test_redacted_path_digest_matches_the_documented_recipe() -> None:
    import hashlib

    digest = hashlib.sha256(b"docs/private.md").hexdigest()[:12]
    assert gate._redact_path(Path("docs") / "private.md") == f"<path sha256:{digest}>"
