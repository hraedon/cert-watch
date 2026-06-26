"""Posture evaluation storage and retrieval."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect, _iso
from cert_watch.database.schema import init_schema


def store_scan_posture(
    db_path: str | Path,
    cert_id: str,
    hostname: str | None,
    port: int | None,
    grade: str,
    findings: list[dict],
    protocol_version: str = "",
    ocsp_stapling: bool | None = None,
    hsts: bool | None = None,
    must_staple: bool = False,
    verify_requested: bool | None = None,
    chain_incomplete: bool = False,
    chain_status: str | None = None,
    caa_present: bool | None = None,
    caa_records: list[str] | None = None,
    scanned_at: str | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Store a posture evaluation result in the scan_posture table.

    Returns the posture entry id. When *conn* is provided it is used
    directly and the caller owns commit/rollback.
    """
    from cert_watch.posture import Finding

    if conn is None:
        init_schema(db_path)
    posture_id = str(uuid.uuid4())
    if scanned_at is None:
        scanned_at = _iso(datetime.now(UTC))

    findings_json = json.dumps([
        {"check": f.check, "status": f.status, "message": f.message}
        if isinstance(f, Finding) else f
        for f in findings
    ])

    params = (
        posture_id,
        cert_id,
        hostname,
        port,
        grade,
        protocol_version,
        1 if ocsp_stapling is True else (0 if ocsp_stapling is False else None),
        1 if hsts is True else (0 if hsts is False else None),
        1 if must_staple else 0,
        1 if verify_requested is True else (0 if verify_requested is False else None),
        1 if chain_incomplete else 0,
        chain_status,
        1 if caa_present is True else (0 if caa_present is False else None),
        json.dumps(caa_records or []),
        findings_json,
        scanned_at,
    )

    if conn is None:
        with _connect(db_path) as conn:
            conn.execute(
                """INSERT INTO scan_posture
                (id, cert_id, hostname, port, grade, protocol_version,
                 ocsp_stapling, hsts, must_staple, verify_requested,
                 chain_incomplete, chain_status, caa_present, caa_records,
                 findings, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            conn.commit()
    else:
        conn.execute(
            """INSERT INTO scan_posture
            (id, cert_id, hostname, port, grade, protocol_version,
             ocsp_stapling, hsts, must_staple, verify_requested,
             chain_incomplete, chain_status, caa_present, caa_records,
             findings, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            params,
        )
    return posture_id


def get_posture_for_cert(db_path: str | Path, cert_id: str) -> dict | None:
    """Get the most recent posture evaluation for a certificate.

    Returns a dict with grade, findings, protocol_version, etc. or None.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_posture WHERE cert_id = ? "
            "ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (cert_id,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["findings"] = (
            json.loads(d["findings"])
            if isinstance(d["findings"], str)
            else d["findings"]
        )
    except (json.JSONDecodeError, TypeError):
        d["findings"] = []
    d["chain_incomplete"] = bool(d.get("chain_incomplete"))
    d["chain_status"] = d.get("chain_status")
    d["caa_present"] = (
        True if d.get("caa_present") == 1 else (False if d.get("caa_present") == 0 else None)
    )
    try:
        d["caa_records"] = (
            json.loads(d["caa_records"])
            if isinstance(d.get("caa_records"), str) and d.get("caa_records")
            else []
        )
    except (json.JSONDecodeError, TypeError):
        d["caa_records"] = []
    return d


def get_posture_grades_for_certs(
    db_path: str | Path, cert_ids: list[str]
) -> dict[str, str]:
    """Get the latest posture grade for each cert_id.

    Returns {cert_id: grade} for certs that have posture data.
    """
    if not cert_ids:
        return {}
    init_schema(db_path)
    with _connect(db_path) as conn:
        ph = ",".join("?" * len(cert_ids))
        # Pick exactly one row per cert_id — the latest by (scanned_at, id).
        # The id tiebreaker makes the result deterministic when two scans
        # share an identical scanned_at timestamp.
        rows = conn.execute(
            f"""SELECT sp.cert_id, sp.grade FROM scan_posture sp
            WHERE sp.cert_id IN ({ph})
              AND sp.id = (
                SELECT sp2.id FROM scan_posture sp2
                WHERE sp2.cert_id = sp.cert_id
                ORDER BY sp2.scanned_at DESC, sp2.id DESC
                LIMIT 1
              )""",
            cert_ids,
        ).fetchall()
    return {r["cert_id"]: r["grade"] for r in rows}


def get_posture_for_certs(
    db_path: str | Path, cert_ids: list[str]
) -> dict[str, dict]:
    """Get the latest full posture row for each cert_id in a single query.

    Same per-cert shape as :func:`get_posture_for_cert`, but batched so a
    fleet-wide report (e.g. the compliance export) doesn't issue one query per
    certificate. Returns ``{cert_id: posture_dict}`` for certs with posture data.
    """
    if not cert_ids:
        return {}
    init_schema(db_path)
    with _connect(db_path) as conn:
        ph = ",".join("?" * len(cert_ids))
        rows = conn.execute(
            f"""SELECT sp.* FROM scan_posture sp
            WHERE sp.cert_id IN ({ph})
              AND sp.id = (
                SELECT sp2.id FROM scan_posture sp2
                WHERE sp2.cert_id = sp.cert_id
                ORDER BY sp2.scanned_at DESC, sp2.id DESC
                LIMIT 1
              )""",
            cert_ids,
        ).fetchall()
    result: dict[str, dict] = {}
    for row in rows:
        d = dict(row)
        try:
            d["findings"] = (
                json.loads(d["findings"])
                if isinstance(d["findings"], str)
                else d["findings"]
            )
        except (json.JSONDecodeError, TypeError):
            d["findings"] = []
        d["chain_incomplete"] = bool(d.get("chain_incomplete"))
        d["chain_status"] = d.get("chain_status")
        d["caa_present"] = (
            True if d.get("caa_present") == 1 else (False if d.get("caa_present") == 0 else None)
        )
        try:
            d["caa_records"] = (
                json.loads(d["caa_records"])
                if isinstance(d.get("caa_records"), str) and d.get("caa_records")
                else []
            )
        except (json.JSONDecodeError, TypeError):
            d["caa_records"] = []
        result[d["cert_id"]] = d
    return result
