# cert-watch

Track expirations of TLS certificates from scanned hosts and uploaded files (PEM / DER / CER / CRT / PKCS#12 `.pfx`), with a simple web dashboard.

> Status: scaffold. The application skeleton boots and serves an empty dashboard at `/`; feature modules (`scan`, `upload`, `alerts`, `scheduler`) are stubs to be implemented against the work-item specs in `docs/spec/`.

## Why this exists

cert-watch is built "traditionally" as a point of comparison for [software-factory-2](../software-factory-2). Same MVP, hand-rolled: see the comparison notes in the parent directory.

## Stack

- Python 3.12 / FastAPI / Jinja2 / `cryptography`
- SQLite (single-file persistence)
- Docker image published to GHCR
- Deploy: Kubernetes (Argo CD GitOps), Docker Compose, or Linux + systemd

## Quick start (local)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m cert_watch        # serves http://localhost:8000
.venv/bin/pytest -q
```

## Docker

```bash
docker build -t cert-watch:dev .
docker run --rm -p 8000:8000 -v cert-watch-data:/var/lib/cert-watch cert-watch:dev
```

Or with compose:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

## Kubernetes (Argo CD)

The cluster pulls from this repo; CI bumps the image tag on `main`. One-time bootstrap:

```bash
kubectl apply -f deploy/argocd/application.yaml
```

After that, every merge to `main` builds + pushes a new image and commits a tag bump to `deploy/k8s/kustomization.yaml`; Argo CD syncs within a minute.

Direct apply (no Argo CD):

```bash
kubectl apply -k deploy/k8s
```

## Linux / systemd

```bash
sudo ./scripts/install-linux.sh   # installs to /opt/cert-watch, enables cert-watch.service
```

See `deploy/systemd/cert-watch.service`.

## Project layout

```
src/cert_watch/        FastAPI app + feature modules
tests/                 pytest suite
docs/spec/             work-item specs (one per FR)
deploy/k8s/            kustomize base for the cluster
deploy/compose/        docker-compose for single-host
deploy/systemd/        bare-metal Linux unit file
deploy/argocd/         Application CR for the cluster
.github/workflows/     CI + image build + tag-bump
```

## License

MIT
