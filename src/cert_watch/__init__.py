__version__ = "0.5.3"
__commit__ = ""


def _load_runtime_version() -> tuple[str, str]:
    try:
        from importlib.resources import files

        vf = files("cert_watch").joinpath("_version.txt")
        if vf.is_file():
            content = vf.read_text().strip()
            parts = [p for p in content.split("\n") if not p.startswith("#")]
            ver = parts[0].lstrip("v") if parts else ""
            commit = parts[1] if len(parts) > 1 else ""
            return ver or __version__, commit
    except OSError:
        pass
    return __version__, __commit__


__version__, __commit__ = _load_runtime_version()
