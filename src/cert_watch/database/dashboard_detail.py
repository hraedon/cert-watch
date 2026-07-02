"""Single-certificate detail query (targeted JOIN replacement)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_rows import _build_dashboard_rows
from cert_watch.database.dashboard_unified import _build_unified_from_dash
from cert_watch.database.posture import get_posture_for_cert
from cert_watch.database.schema import init_schema


def get_cert_detail(db_path: str | Path, cert_id: str) -> dict[str, Any] | None:
    """Return a single leaf certificate's dashboard row with chain + posture.

    Targeted JOIN replacement for scanning the full unified list to find one
    cert.  Returns a rich dashboard dict (same shape as the dashboard rows)
    augmented with ``posture`` (latest posture evaluation or ``None``) and
    host context (owner/renewal fields) when the cert maps to a tracked host.
    Returns ``None`` if no leaf cert with that id exists.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        leaf = conn.execute(
            "SELECT * FROM certificates WHERE id = ? AND is_leaf = 1", (cert_id,)
        ).fetchone()
        if leaf is None:
            return None
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ?", (cert_id,)
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        host_rows = []
        scan_rows = []
        if leaf["hostname"]:
            host_rows = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (leaf["hostname"], leaf["port"]),
            ).fetchall()
            scan_rows = conn.execute(
                """
                SELECT hostname, port, status, scanned_at, error_message
                FROM scan_history sh1
                WHERE sh1.hostname = ? AND sh1.port = ?
                  AND scanned_at = (
                    SELECT MAX(scanned_at) FROM scan_history sh2
                    WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
                  )
                """,
                (leaf["hostname"], leaf["port"]),
            ).fetchall()

    dash = _build_dashboard_rows([leaf, *chain_rows], anchor_rows)
    if not dash:
        return None
    if host_rows:
        unified = _build_unified_from_dash(dash, host_rows, scan_rows)
        row = next((e for e in unified if e.get("id") == cert_id), dash[0])
    else:
        row = dash[0]
        row["kind"] = "uploaded" if leaf["source"] != "scanned" else "scanned"
    row["posture"] = get_posture_for_cert(db_path, cert_id)
    return row
