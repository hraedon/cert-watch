from fastapi.testclient import TestClient

from cert_watch.app import create_app
from cert_watch.config import Settings
from cert_watch.database import _connect, init_schema
from cert_watch.database.users_roles import Role, SqliteRoleRepository, SqliteUserRepository, User


def _setup_db_with_role(tmp_path, role_email="platform@example.com"):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    role_repo = SqliteRoleRepository(db)
    user_repo = SqliteUserRepository(db)
    role = Role(name="Platform", email=role_email)
    role_id = role_repo.add(role)
    user = User(username="alice", email="alice@example.com", role_id=role_id)
    user_repo.add(user)
    return db, role_id


def _insert_cert_and_host(
    db,
    hostname="app.example.com",
    port=443,
    owner_email="platform@example.com",
    days_remaining=365,
    cert_id="cert-1",
):
    from datetime import UTC, datetime, timedelta

    not_after = (datetime.now(UTC) + timedelta(days=days_remaining)).isoformat()
    not_before = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO hosts (hostname, port, owner_email, added_at) "
            "VALUES (?, ?, ?, datetime('now'))",
            (hostname, port, owner_email),
        )
        conn.execute(
            "INSERT INTO certificates "
            "(id, subject, issuer, not_before, not_after, hostname, port, "
            "fingerprint_sha256, raw_der, is_leaf, source, san_dns_names, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'scanned', '[]', "
            "datetime('now'), datetime('now'))",
            (
                cert_id, f"CN={hostname}", "CN=Test CA",
                not_before, not_after, hostname, port,
                f"sha256{cert_id}", b"\x00",
            ),
        )
        conn.commit()


def _make_authed_app(tmp_path):
    db, role_id = _setup_db_with_role(tmp_path)
    _insert_cert_and_host(db)

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    return app, db


def test_team_route_shows_team_certs(tmp_path):
    app, db = _make_authed_app(tmp_path)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    assert "Platform" in r.text
    assert "app.example.com" in r.text


def test_team_route_no_user_role(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    user_repo = SqliteUserRepository(db)
    user_repo.add(User(username="bob", email="bob@example.com", role_id=""))

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("bob")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    assert "No team assigned" in r.text


def test_role_based_alert_routing(tmp_path):
    from cert_watch.alerts import evaluate_all_certs
    from cert_watch.database import SqliteAlertRepository

    db, role_id = _setup_db_with_role(tmp_path)
    _insert_cert_and_host(db, days_remaining=3)

    alert_repo = SqliteAlertRepository(db)
    alerts = evaluate_all_certs(db, alert_repo)

    assert len(alerts) >= 1
    alert = alerts[0]
    assert "alice@example.com" in alert.extra_recipients


def test_nav_link_for_authenticated_users(tmp_path):
    app, db = _make_authed_app(tmp_path)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/")
    assert r.status_code == 200
    assert 'href="/team"' in r.text


def test_nav_link_hidden_for_unauthenticated(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    from cert_watch.app import app as module_app

    with TestClient(module_app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert 'href="/team"' not in r.text


# ---- H1: Pagination ----


def test_team_pagination_defaults_to_page_1(tmp_path):
    """Team dashboard with one cert shows page 1 of 1 (no pagination nav)."""
    app, db = _make_authed_app(tmp_path)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    # Single cert — no pagination controls needed
    assert "Page 1 of 1" not in r.text and "cw-pagination" not in r.text


def test_team_pagination_with_many_certs(tmp_path):
    """Team dashboard with > 25 certs shows pagination controls."""
    db, role_id = _setup_db_with_role(tmp_path)
    # Insert 30 certs to exceed the per_page=25 default
    for i in range(30):
        _insert_cert_and_host(
            db,
            hostname=f"host{i}.example.com",
            port=443,
            cert_id=f"cert-{i}",
        )

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    # Should have pagination controls
    assert "cw-pagination" in r.text
    assert "Page 1 of 2" in r.text
    assert "Next" in r.text

    # Page 2
    r2 = client.get("/team?page=2")
    assert r2.status_code == 200
    assert "Prev" in r2.text


def test_team_pagination_page_param_clamped(tmp_path):
    """Asking for page 999 returns the last valid page, not a 404."""
    app, db = _make_authed_app(tmp_path)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team?page=999")
    assert r.status_code == 200
    # Should clamp to page 1 (only 1 cert)
    assert "app.example.com" in r.text


# ---- H2: Urgency includes chain status ----


def test_urgency_considers_chain_incomplete(tmp_path):
    """A cert with healthy leaf days but incomplete chain should show Warning."""
    db, role_id = _setup_db_with_role(tmp_path)
    _insert_cert_and_host(db, days_remaining=365)

    # Insert a scan_posture row with chain_status='incomplete'
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO scan_posture "
            "(id, cert_id, grade, findings, scanned_at, chain_status) "
            "VALUES (?, ?, 'A', '[]', datetime('now'), 'incomplete')",
            ("sp-1", "cert-1"),
        )
        conn.commit()

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    # The cert should be Warning (not Healthy) due to incomplete chain
    assert "Warning" in r.text


def test_urgency_considers_chain_child_expiry(tmp_path):
    """A cert whose chain child expires sooner should use the child's urgency."""
    db, role_id = _setup_db_with_role(tmp_path)
    _insert_cert_and_host(db, days_remaining=365)

    from datetime import UTC, datetime, timedelta

    # Add a chain cert expiring in 10 days
    chain_not_after = (datetime.now(UTC) + timedelta(days=10)).isoformat()
    chain_not_before = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO certificates "
            "(id, subject, issuer, not_before, not_after, hostname, port, "
            "fingerprint_sha256, raw_der, is_leaf, source, san_dns_names, "
            "created_at, updated_at, parent_cert_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'scanned', '[]', "
            "datetime('now'), datetime('now'), ?)",
            (
                "chain-1", "CN=Intermediate CA", "CN=Root CA",
                chain_not_before, chain_not_after, "app.example.com", 443,
                "sha256chain1", b"\x00", "cert-1",
            ),
        )
        conn.commit()

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    # The cert should be Warning because the chain child expires in < 30 days
    assert "Warning" in r.text


# ---- H3: Stat card label ----


def test_stat_card_label_says_30_days(tmp_path):
    """The warning stat card should say '< 30 days', not '≤ 14 days'."""
    app, db = _make_authed_app(tmp_path)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200
    assert "Expiring &lt; 30 days" in r.text
    assert "≤ 14 days" not in r.text


# ---- H6: Pre-migration error handling ----


def test_team_route_handles_missing_users_table(tmp_path):
    """When users/roles tables don't exist, route gracefully shows empty state.

    Drops the users/roles tables after init_schema to simulate a
    pre-migration DB, then verifies the /team route returns 200 with the
    "No team assigned" empty state instead of a 500.
    """
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    # Drop users and roles tables to simulate pre-migration DB
    with _connect(db) as conn:
        conn.execute("DROP TABLE users")
        conn.execute("DROP TABLE roles")
        conn.commit()

    s = Settings(db_path=db, data_dir=tmp_path)

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice")
    with TestClient(app, raise_server_exceptions=False) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/team")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
    assert "No team assigned" in r.text


# ---- H5: Alert routing logs on failure ----


def test_alert_routing_logs_on_failure(tmp_path, caplog):
    """Role-based alert routing should log debug on exception."""
    import logging

    from cert_watch.alerts import evaluate_all_certs
    from cert_watch.database import SqliteAlertRepository

    db, role_id = _setup_db_with_role(tmp_path)
    _insert_cert_and_host(db, days_remaining=3)

    alert_repo = SqliteAlertRepository(db)

    # Monkeypatch the role repo to raise
    from cert_watch.database import users_roles

    original_list_all = users_roles.SqliteRoleRepository.list_all

    def _raising_list_all(self):
        raise RuntimeError("test error")

    users_roles.SqliteRoleRepository.list_all = _raising_list_all
    try:
        with caplog.at_level(logging.DEBUG, logger="cert_watch.alerts"):
            evaluate_all_certs(db, alert_repo)
        # Should not raise, and should log
        assert any(
            "Role-based alert routing unavailable" in rec.message
            for rec in caplog.records
        ), f"Expected debug log not found in: {[r.message for r in caplog.records]}"
    finally:
        users_roles.SqliteRoleRepository.list_all = original_list_all


# ---- H7: N+1 query fix in alert routing ----


def test_alert_routing_no_n_plus_1(tmp_path, monkeypatch):
    """_user_repo.list_all() should be called once, not once per role."""
    from cert_watch.alerts import evaluate_all_certs
    from cert_watch.database import SqliteAlertRepository

    db, role_id = _setup_db_with_role(tmp_path)
    # Add a second role to ensure loop iterates
    role_repo = SqliteRoleRepository(db)
    role_repo.add(Role(name="Backend", email="backend@example.com"))
    _insert_cert_and_host(db, days_remaining=3)

    alert_repo = SqliteAlertRepository(db)

    # Track how many times list_all is called on the user repo
    from cert_watch.database import users_roles

    call_count = 0
    original_list_all = users_roles.SqliteUserRepository.list_all

    def _counting_list_all(self):
        nonlocal call_count
        call_count += 1
        return original_list_all(self)

    users_roles.SqliteUserRepository.list_all = _counting_list_all
    try:
        evaluate_all_certs(db, alert_repo)
    finally:
        users_roles.SqliteUserRepository.list_all = original_list_all

    # Should be called exactly once, not once per role
    assert call_count == 1, f"Expected 1 call to list_all, got {call_count}"
