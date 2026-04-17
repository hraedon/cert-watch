"""cert-watch main entry point."""

import uvicorn

from .app_factory import create_app


def main():
    """Run the cert-watch application."""
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
