# MinIO Manager Service

A centralized FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration.


**Details to be added here**


### Testing

```bash
# Install dependencies (only required on first run or when the uv.lock file changes)
uv sync --locked

# Run tests
PYTHONPATH=. uv run pytest tests

# Run with coverage
PYTHONPATH=. uv run pytest --cov=src tests/
```
