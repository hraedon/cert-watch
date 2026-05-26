from cert_watch.certificate_model import Certificate
from cert_watch.database import init_schema
from cert_watch.scan import ScannedEntry, store_scanned


def test_re_scan_sets_replaces_cert_id(tmp_path, self_signed_leaf, chain_triplet, monkeypatch):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf1 = self_signed_leaf
    from cert_watch.certificate_model import parse_certificate

    cert1 = parse_certificate(leaf1.der)
    assert isinstance(cert1, Certificate)

    entry1 = ScannedEntry(host="renew.example.com", port=443, leaf=cert1, chain=[])
    first_id = store_scanned(entry1, db)

    inter = chain_triplet["intermediate"]
    new_cert = parse_certificate(inter.der)
    assert isinstance(new_cert, Certificate)

    entry2 = ScannedEntry(host="renew.example.com", port=443, leaf=new_cert, chain=[])
    second_id = store_scanned(entry2, db)

    assert first_id != second_id

    with __import__("sqlite3").connect(str(db)) as conn:
        row = conn.execute(
            "SELECT replaces_cert_id FROM certificates WHERE id = ?", (second_id,)
        ).fetchone()
    assert row[0] == first_id


def test_first_scan_has_no_replaces(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    from cert_watch.certificate_model import parse_certificate

    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    entry = ScannedEntry(host="fresh.example.com", port=443, leaf=cert, chain=[])
    leaf_id = store_scanned(entry, db)

    with __import__("sqlite3").connect(str(db)) as conn:
        row = conn.execute(
            "SELECT replaces_cert_id FROM certificates WHERE id = ?", (leaf_id,)
        ).fetchone()
    assert row[0] is None


def test_dashboard_includes_replaces_info(tmp_path, self_signed_leaf):
    from cert_watch.database import list_dashboard_rows

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.certificate_model import parse_certificate

    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    entry = ScannedEntry(host="dash.example.com", port=443, leaf=cert, chain=[])
    first_id = store_scanned(entry, db)

    entry2 = ScannedEntry(host="dash.example.com", port=443, leaf=cert, chain=[])
    store_scanned(entry2, db)

    rows = list_dashboard_rows(db)
    assert len(rows) >= 1
    leaf_row = next(r for r in rows if r["host"] == "dash.example.com:443")
    assert leaf_row["replaces_cert_id"] == first_id
