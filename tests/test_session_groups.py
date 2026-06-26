"""BC-150: group/role lists survive the session-token round-trip intact.

LDAP/AD group values are DNs containing commas (``CN=admins,OU=Groups,DC=…``).
The old ``,``-join encoding shredded each DN into RDN fragments, so the decoded
groups never matched the configured role-map DNs and every user silently fell
back to ``viewer`` — i.e. RBAC was inert for the primary (AD) deployment.
"""

from __future__ import annotations

from cert_watch.auth import create_session, decode_session
from cert_watch.auth.rbac import ROLE_ADMIN
from cert_watch.auth.session import _decode_list, _encode_list

_DN_GROUPS = [
    "CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com",
    "CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com",
]


def test_encode_decode_list_roundtrip_preserves_dns():
    assert _decode_list(_encode_list(_DN_GROUPS)) == _DN_GROUPS


def test_encode_decode_handles_empty_and_special_chars():
    assert _decode_list(_encode_list([])) == []
    weird = ["a,b", 'c"d', "e:f", "g=h,i=j"]
    assert _decode_list(_encode_list(weird)) == weird


def test_decode_list_fails_closed_on_garbage():
    # Pre-JSON tokens / corruption decode to [] (no roles), never an exception.
    assert _decode_list("!!!not-base64!!!") == []


def test_session_roundtrip_preserves_dn_groups_and_roles():
    token = create_session("alice", groups=_DN_GROUPS, roles=["app-admin"])
    info = decode_session(token)
    assert info is not None
    assert info.groups == _DN_GROUPS
    assert info.roles == ["app-admin"]


def test_dn_groups_resolve_to_role_via_role_map():
    """The end-to-end point: a DN group must still match a role-map entry."""
    from cert_watch.auth.rbac import build_auth_context

    token = create_session("alice", groups=_DN_GROUPS)
    info = decode_session(token)
    assert info is not None
    role_map = {
        "admin": {"groups": ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]}
    }
    ctx = build_auth_context("alice", info.groups, info.roles, role_map)
    assert ROLE_ADMIN in ctx.roles
    assert ctx.may_write()


# ---------------------------------------------------------------------------
# Cookie-overflow fix: only role-map-relevant claims are stored in the session.
# A full AD memberOf list overflows the ~4 KB cookie limit and the browser
# silently drops it, causing a post-login redirect loop.
# ---------------------------------------------------------------------------

# A realistic AD user: in many groups, only one of which the role map cares about.
_MANY_GROUPS = [
    f"CN=app-group-{i:03d},OU=Security Groups,OU=Corp,DC=ad,DC=hraedon,DC=com"
    for i in range(80)
] + ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]

_ROLE_MAP = {"admin": {"groups": ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]}}


def test_claims_for_session_keeps_only_role_map_groups():
    from cert_watch.auth.rbac import claims_for_session

    groups, roles = claims_for_session(_MANY_GROUPS, [], _ROLE_MAP)
    assert groups == ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]
    assert roles == []


def test_claims_for_session_empty_when_no_role_map():
    from cert_watch.auth.rbac import claims_for_session

    assert claims_for_session(_MANY_GROUPS, ["some-role"], {}) == ([], [])


def test_claims_filtering_is_behaviour_preserving():
    """Filtering must not change the resolved role for any role map."""
    from cert_watch.auth.rbac import build_auth_context, claims_for_session

    full = build_auth_context("bob", _MANY_GROUPS, [], _ROLE_MAP)
    g, r = claims_for_session(_MANY_GROUPS, [], _ROLE_MAP)
    filtered = build_auth_context("bob", g, r, _ROLE_MAP)
    assert filtered.roles == full.roles
    assert filtered.permissions == full.permissions
    assert ROLE_ADMIN in filtered.roles


def test_full_memberof_overflows_but_filtered_token_fits():
    """create_session auto-truncates groups to stay under the cookie limit.
    The claims_for_session path (used at login) additionally filters to
    role-map-relevant groups so RBAC still works."""
    from cert_watch.auth.rbac import claims_for_session
    from cert_watch.auth.session import _MAX_SAFE_SESSION_BYTES

    overflowing = create_session("carol", groups=_MANY_GROUPS, roles=[])
    # After Plan-048/BC-081 hardening, create_session itself trims the groups
    # list when the token would exceed the browser cookie limit.
    assert len(overflowing.encode()) <= _MAX_SAFE_SESSION_BYTES

    g, r = claims_for_session(_MANY_GROUPS, [], _ROLE_MAP)
    fitted = create_session("carol", groups=g, roles=r)
    assert len(fitted.encode()) <= _MAX_SAFE_SESSION_BYTES
    info = decode_session(fitted)
    assert info is not None
    assert info.groups == ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]


def test_login_path_emits_small_cookie_for_user_in_many_groups(reload_app):
    """Integration guard: a real POST /login for an AD user in many groups must
    emit a cw_auth cookie well under the browser limit, and authenticate the
    next request. This fails if routes/auth.py stops filtering claims — the
    unit tests above can't catch that, only this end-to-end check does.
    """
    import json

    from starlette.testclient import TestClient

    from cert_watch.auth.protocol import AuthResult
    from cert_watch.auth.session import _MAX_SAFE_SESSION_BYTES

    role_map = {"admin": {"groups": ["CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com"]}}
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
        CERT_WATCH_ROLE_MAP=json.dumps(role_map),
    )

    class _FakeLdap:
        provider_name = "ldap"
        supports_form_login = True

        def authenticate(self, username: str, password: str) -> AuthResult:
            return AuthResult(success=True, username=username, groups=_MANY_GROUPS, roles=[])

    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        # Swap in a provider that returns a large memberOf, like a real AD user.
        app_mod.app.state.auth_provider = _FakeLdap()
        r = client.post(
            "/login",
            data={"username": "pmerritt", "password": "x"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        cookie = client.cookies.get("cw_auth")
        assert cookie is not None
        # The whole point: the cookie stays comfortably under the browser limit.
        assert len(cookie) < _MAX_SAFE_SESSION_BYTES
        # ...and the session actually works on the next request (no login loop).
        assert client.get("/").status_code == 200
