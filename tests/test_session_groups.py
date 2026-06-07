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
