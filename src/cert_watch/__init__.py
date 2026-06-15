__version__ = "0.0.0"
__commit__ = ""


def _load_runtime_version() -> tuple[str, str]:
    """Resolve the running (version, commit).

    The installed package metadata is the single source of truth for the
    version number (it derives from pyproject, so it can never drift). A
    ``_version.txt`` baked into the package by the container build supplies the
    commit hash, and acts as a version fallback only when metadata is
    unavailable — e.g. running from a source tree that was never installed.
    """
    version = ""
    commit = ""
    try:
        from importlib.resources import files

        vf = files("cert_watch").joinpath("_version.txt")
        if vf.is_file():
            parts = [
                p for p in vf.read_text().strip().split("\n") if not p.startswith("#")
            ]
            if parts and parts[0].strip():
                version = parts[0].strip().lstrip("v")
            if len(parts) > 1:
                commit = parts[1].strip()
    except OSError:
        pass
    try:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _pkg_version

        try:
            version = _pkg_version("cert-watch")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    return (version or "0.0.0"), commit


__version__, __commit__ = _load_runtime_version()
