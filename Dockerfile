# syntax=docker/dockerfile:1.7
# Pinned digest at 2026-06-03 (python:3.13-slim)
FROM python:3.13-slim@sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3 AS builder

ARG GIT_TAG=0.5.0
ARG GIT_COMMIT=unknown

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml README.md uv.lock ./
COPY src ./src

RUN printf '%s\n%s\n' "$GIT_TAG" "$GIT_COMMIT" > src/cert_watch/_version.txt
RUN uv sync --frozen --no-dev --no-install-project
RUN uv pip install --no-deps . --python /build/.venv/bin/python
# Fix shebangs so scripts point to the runtime venv path (/opt/venv)
RUN sed -i 's|/build/.venv/bin/python|/opt/venv/bin/python|g' /build/.venv/bin/*

# Pinned digest at 2026-06-03 (python:3.13-slim)
FROM python:3.13-slim@sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3 AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERT_WATCH_DATA_DIR=/var/lib/cert-watch

RUN groupadd -r cw && useradd -r -g cw -d /var/lib/cert-watch cw \
    && mkdir -p /var/lib/cert-watch && chown -R cw:cw /var/lib/cert-watch

COPY --from=builder /build/.venv /opt/venv

USER cw
WORKDIR /var/lib/cert-watch
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

ENTRYPOINT ["cert-watch"]
