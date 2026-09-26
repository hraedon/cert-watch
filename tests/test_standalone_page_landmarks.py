"""Every standalone HTML document carries one ``<main>`` landmark (#126 S2).

``base.html`` children are covered in the browser by
``tests/e2e/test_landmarks_labels.py``. The sign-in, setup and auth-continue
pages are their own documents and are hard to reach from that suite (the e2e
server runs with auth disabled), so check their source here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parent.parent / "src" / "cert_watch" / "templates"
DOCUMENTS = sorted(
    p for p in TEMPLATES.rglob("*.html") if "<!doctype" in p.read_text(encoding="utf-8").lower()
)


def test_documents_found() -> None:
    names = {p.name for p in DOCUMENTS}
    assert {"base.html", "login.html", "setup.html", "auth_continue.html"} <= names


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_document_has_exactly_one_main(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert len(re.findall(r"<main\b", text)) == 1, f"{path.name}: expected one <main>"
    assert text.count("</main>") == 1


def test_health_check_unavailable_is_warn_not_crit() -> None:
    """An unreachable health endpoint is a monitoring problem: warn (#126 S2)."""
    js = (TEMPLATES.parent / "static" / "js" / "core.js").read_text(encoding="utf-8")
    block = js[: js.index("'Health check unavailable'")].rsplit("strip.className", 1)[1]
    assert "t-warn" in block and "t-crit" not in block
