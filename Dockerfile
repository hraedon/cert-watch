# syntax=docker/dockerfile:1.7
# Pinned digest at 2026-06-11 (python:3.13-slim)
FROM python:3.13-slim@sha256:c8c127005665ea0ab700577dca2b412d3c32d844cc3916886042b432f5848121 AS builder

ARG GIT_TAG=0.5.0
ARG GIT_COMMIT=unknown

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
# Pinned digest at 2026-07-09 (uv 0.11.28).
COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv

COPY pyproject.toml README.md uv.lock ./
COPY src ./src

RUN printf '%s\n%s\n' "$GIT_TAG" "$GIT_COMMIT" > src/cert_watch/_version.txt
RUN uv sync --frozen --no-dev --no-install-project
RUN uv pip install --no-deps . --python /build/.venv/bin/python
# Fix shebangs so scripts point to the runtime venv path (/opt/venv)
RUN sed -i 's|/build/.venv/bin/python|/opt/venv/bin/python|g' /build/.venv/bin/*

# Pinned digest at 2026-06-11 (python:3.13-slim)
FROM python:3.13-slim@sha256:c8c127005665ea0ab700577dca2b412d3c32d844cc3916886042b432f5848121 AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERT_WATCH_DATA_DIR=/var/lib/cert-watch

# Debian security patches newer than the pinned base digest — the trivy
# release gate fails on fixed-status HIGH/CRITICAL CVEs (e.g. libssl) faster
# than upstream rebuilds python:slim.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r cw && useradd -r -g cw -d /var/lib/cert-watch cw \
    && mkdir -p /var/lib/cert-watch && chown -R cw:cw /var/lib/cert-watch

COPY --from=builder /build/.venv /opt/venv

USER cw
WORKDIR /var/lib/cert-watch
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

ENTRYPOINT ["cert-watch"]
