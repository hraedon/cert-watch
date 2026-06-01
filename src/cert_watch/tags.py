"""Tag parsing/formatting.

Tags are stored as a comma-separated free-form string (the existing
``hosts.tags`` convention, extended to certificates). These helpers normalize
between that string form and a list of labels:

- split on commas, trim whitespace, drop empties
- de-dupe case-insensitively, preserving first-seen casing and order

See plan 013.
"""

from __future__ import annotations

from collections.abc import Iterable


def parse_tags(raw: str | None) -> list[str]:
    """Parse a comma-separated tag string into a normalized list of labels."""
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        label = part.strip()
        if not label:
            continue
        key = label.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(label)
    return out


def format_tags(tags: Iterable[str]) -> str:
    """Render a list of labels back to the canonical comma-separated string."""
    return ",".join(parse_tags(",".join(t for t in tags if t)))


def merge_tags(*sources: str | Iterable[str] | None) -> list[str]:
    """Union several tag sources (strings or lists) into one normalized list.

    Used to compute a cert's *effective* tags from its own tags plus its host's.
    """
    parts: list[str] = []
    for src in sources:
        if src is None:
            continue
        if isinstance(src, str):
            parts.extend(parse_tags(src))
        else:
            parts.extend(parse_tags(",".join(t for t in src if t)))
    return parse_tags(",".join(parts))


def tags_match(effective: Iterable[str], match_tags: Iterable[str]) -> bool:
    """True if any normalized tag appears in both sets (case-insensitive)."""
    eff = {t.casefold() for t in effective}
    return any(m.casefold() in eff for m in match_tags)
