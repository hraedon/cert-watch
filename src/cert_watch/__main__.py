import logging
import os

import uvicorn

logger = logging.getLogger("cert_watch")


def main() -> None:
    port_str = os.environ.get("CERT_WATCH_PORT", "8000")
    try:
        port = int(port_str)
    except ValueError:
        logger.warning("Invalid CERT_WATCH_PORT=%r, using default 8000", port_str)
        port = 8000
    uvicorn.run(
        "cert_watch.app:app",
        host=os.environ.get("CERT_WATCH_HOST", "0.0.0.0"),
        port=port,
        reload=os.environ.get("CERT_WATCH_RELOAD") == "1",
    )


if __name__ == "__main__":
    main()
