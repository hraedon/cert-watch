"""Browser markers must follow the directory boundary during real collection."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

_ROOT = Path(__file__).resolve().parents[1]
_UNIT = {
    "tests/test_regular.py::test_sentinel",
    "tests/test_e2e_import_guard.py::test_sentinel",
    "tests/e2e_helpers/test_helper_unit.py::test_sentinel",
}
_BROWSER = {
    "tests/e2e/test_browser.py::test_sentinel",
    "tests/e2e/nested/test_nested_browser.py::test_sentinel",
    "tests/test_explicit.py::test_sentinel",
}


@pytest.mark.parametrize("checkout_name", ["project", "e2e-checkout"])
@pytest.mark.parametrize("selection", [None, "e2e", ""])
def test_collection_marker_directory_boundary(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
    checkout_name: str,
    selection: str | None,
) -> None:
    """Load the real conftest in a tiny checkout, without launching browsers."""
    checkout = pytester.path / checkout_name
    for nodeid in sorted(_UNIT | _BROWSER):
        target = checkout / nodeid.split("::", 1)[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        marker = (
            "import pytest\npytestmark = pytest.mark.e2e\n\n"
            if target.name == "test_explicit.py"
            else ""
        )
        target.write_text(marker + "def test_sentinel():\n    pass\n", encoding="utf-8")
    shutil.copyfile(_ROOT / "tests/e2e/conftest.py", checkout / "tests/e2e/conftest.py")
    config = checkout / "pytest.ini"
    config.write_text(
        "[pytest]\naddopts = -m 'not e2e'\nmarkers = e2e: browser tests\n",
        encoding="utf-8",
    )
    # The real conftest imports its seed helper, but none of its server fixtures
    # run. Disable optional plugins in the child, including visual cleanup.
    monkeypatch.setenv("PYTHONPATH", str(_ROOT))
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    args = [str(checkout), "-c", str(config), "-v", "--color=no", "-p", "no:cacheprovider"]
    if selection is not None:
        args += ["-m", selection]
    result = pytester.runpytest_subprocess(*args)
    expected = _UNIT if selection is None else _BROWSER if selection else _UNIT | _BROWSER
    result.assert_outcomes(passed=len(expected), deselected=6 - len(expected))
    selected = {
        nodeid.removeprefix(checkout_name + "/")
        for nodeid in re.findall(r"^(\S+) PASSED", result.stdout.str(), re.MULTILINE)
    }
    assert selected == expected
