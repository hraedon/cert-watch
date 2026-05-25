import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "cert_watch.app:app",
        host=os.environ.get("CERT_WATCH_HOST", "0.0.0.0"),
        port=int(os.environ.get("CERT_WATCH_PORT", "8000")),
        reload=os.environ.get("CERT_WATCH_RELOAD") == "1",
    )


if __name__ == "__main__":
    main()
