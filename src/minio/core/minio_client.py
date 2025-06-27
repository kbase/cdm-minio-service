import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import aiobotocore.session

from ...service.exceptions import ConnectionError
from ..models.minio_config import MinIOConfig

logger = logging.getLogger(__name__)


class MinIOClient:
    """MinIO Client Wrapper."""

    def __init__(self, config: MinIOConfig):
        """
        Initializes the MinIOClient with server configuration.

        Args:
            config: A MinIOConfig object with connection details.
        """
        self.config = config
        self._session = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self._initialize_session()
        return self

    async def __aexit__(self):
        """Async context manager exit."""
        await self._close_session()

    async def _initialize_session(self):
        """Initialize the aiobotocore session."""
        try:
            self._session = aiobotocore.session.get_session()
            logger.info("Initialized async MinIO client session")
        except Exception as e:
            logger.error(f"Failed to initialize MinIO session: {e}")
            raise ConnectionError(f"Failed to initialize session: {e}") from e

    async def _close_session(self):
        """Close the session and cleanup resources."""
        if self._session:
            # aiobotocore sessions don't need explicit closing
            self._session = None
            logger.info("Closed MinIO client session")

    @asynccontextmanager
    async def _get_client(self) -> AsyncIterator[Any]:
        """Get an async S3 client with proper configuration."""
        if not self._session:
            await self._initialize_session()

        async with self._session.create_client(  # type: ignore
            "s3",
            endpoint_url=str(self.config.endpoint),
            aws_access_key_id=self.config.access_key,
            aws_secret_access_key=self.config.secret_key,
            use_ssl=self.config.secure,
        ) as client:
            yield client

    async def test_connection(self) -> bool:
        """
        Verifies the connection to the MinIO server by listing buckets.

        Returns:
            True if the connection is successful, False otherwise.
        """
        try:
            async with self._get_client() as client:
                response = await client.list_buckets()
                bucket_count = len(response.get("Buckets", []))
                logger.info(
                    f"Connection test successful. Found {bucket_count} buckets."
                )
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
