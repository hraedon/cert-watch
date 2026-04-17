# cert-watch Tests

This directory contains test files mirroring the source structure.

- `conftest.py` — Pytest fixtures and configuration
- `core/` — Tests for core utilities
- `models/` — Tests for data models
- `repositories/` — Tests for repository implementations
- `services/` — Tests for service layer
- `web/` — Tests for web layer and routes

## Running Tests

```bash
pip install -e .[dev]
pytest
```
