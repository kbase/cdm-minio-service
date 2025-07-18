# MinIO Manager Service

A centralized FastAPI service to manage MinIO users, groups, and policies for data governance with KBase authentication integration.

## ⚠️ **CRITICAL DEPLOYMENT WARNING**

**🚨 SINGLE INSTANCE ONLY - DO NOT DEPLOY MULTIPLE INSTANCES 🚨**

This service has a known race condition issue with concurrent policy updates when multiple instances are running. Deploying multiple instances will result in:

- **Data Loss**: Concurrent policy updates can overwrite each other
- **Permission Issues**: Users may lose access to paths they should have  
- **Silent Failures**: No error indication when race conditions occur

**Issue Reference**: [kbase/cdm-minio-service#25](https://github.com/kbase/cdm-minio-service/issues/25)

Until this issue is resolved, **always deploy exactly ONE instance** of this service.

---



### Testing

```bash
# Install dependencies (only required on first run or when the uv.lock file changes)
uv sync --locked

# Run tests
PYTHONPATH=. uv run pytest tests

# Run with coverage
PYTHONPATH=. uv run pytest --cov=src tests/
```
