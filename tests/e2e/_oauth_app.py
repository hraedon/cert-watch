"""Run cert-watch with loopback allowed as an outbound transport (#98 tests).

The SSRF guard blocks 127.0.0.0/8 unconditionally, which is right in
production and makes a local mock IdP unreachable from the server's
discovery, token and JWKS calls. The unit suite lifts that for the transport
under test with ``allow_loopback_transport``; the browser tests run the app in
a subprocess, so this launcher applies the same override before handing over
to the normal entry point. Only the e2e suite uses it.
"""

from __future__ import annotations

import importlib
import sys

from tests._integration_servers import _IS_BLOCKED_IP_PATCH_TARGETS, _make_loopback_allowed


def _allow_loopback() -> None:
    from cert_watch.scan_resolver import _is_blocked_ip

    wrapped = _make_loopback_allowed(_is_blocked_ip)
    for target in _IS_BLOCKED_IP_PATCH_TARGETS:
        module_name, attr = target.rsplit(".", 1)
        module = importlib.import_module(module_name)
        if hasattr(module, attr):
            setattr(module, attr, wrapped)


if __name__ == "__main__":
    _allow_loopback()
    from cert_watch.__main__ import main

    main(sys.argv[1:])
