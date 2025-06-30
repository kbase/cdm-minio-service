"""
Generic Resource Manager for eliminating CRUD duplication.

This module provides a generic base class that abstracts common resource
management patterns across different MinIO resource types (users, groups, policies, etc.).
"""

import logging
import os
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator, Generic, List, Optional, TypeVar

from ...service.exceptions import MinIOManagerError
from ..core.base_executor import BaseMinIOExecutor
from ..core.command_builder import MinIOCommandBuilder
from ..core.minio_client import MinIOClient
from ..models.minio_config import MinIOConfig

# Generic type for resource models
T = TypeVar("T")

logger = logging.getLogger(__name__)

DEFAULT_ALIAS = "minio_api"


class ResourceManager(ABC, Generic[T]):
    """
    Generic base class for MinIO resource management.

    This class provides common CRUD operations and patterns that are shared
    across different resource types (users, groups, policies, etc.).

    Type parameter T represents the resource model type (UserModel, GroupModel, etc.).
    """

    def __init__(
        self,
        client: MinIOClient,
        config: MinIOConfig,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the resource manager.

        Args:
            client: Async MinIO client instance
            config: MinIO configuration
            logger_instance: Optional logger instance
        """
        self.client = client
        self.config = config
        self.logger = logger_instance or logging.getLogger(self.__class__.__name__)

        # Initialize executor and command infrastructure
        self._executor = BaseMinIOExecutor(config)
        self.alias = os.environ.get("MINIO_API_ALIAS", DEFAULT_ALIAS)
        self._command_builder = MinIOCommandBuilder(self.alias)

    async def ensure_executor_setup(self) -> None:
        """Ensure the MC executor is properly set up."""
        await self._executor.setup()

    @asynccontextmanager
    async def operation_context(self, operation: str) -> AsyncIterator[None]:
        """
        Async context manager for operations with logging and error handling.

        Args:
            operation: Name of the operation
        """
        self.logger.info(f"Starting {operation}")

        try:
            # Ensure executor is set up for MC operations
            await self.ensure_executor_setup()
            yield
            self.logger.info(f"Completed {operation}")
        except Exception as e:
            self.logger.error(f"Failed {operation}: {e}")
            # Re-raise with appropriate MinIO exception type
            if isinstance(e, MinIOManagerError):
                raise
            else:
                raise MinIOManagerError(f"{operation} failed: {str(e)}") from e

    # === Abstract Methods (must be implemented by subclasses) ===

    @abstractmethod
    def get_resource_type(self) -> str:
        """Get the resource type name (e.g., 'user', 'group', 'policy')."""
        pass

    @abstractmethod
    def get_resource_name_field(self) -> str:
        """Get the field name used for resource identification (e.g., 'username', 'group_name')."""
        pass

    @abstractmethod
    def validate_resource_name(self, name: str) -> str:
        """
        Validate and normalize a resource name.

        Args:
            name: Resource name to validate

        Returns:
            Validated and normalized name

        Raises:
            ValueError: If name is invalid
        """
        pass

    @abstractmethod
    def build_exists_command(self, name: str) -> List[str]:
        """
        Build command to check if resource exists.

        Args:
            name: Resource name

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def build_list_command(self) -> List[str]:
        """
        Build command to list all resources.

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def build_delete_command(self, name: str) -> List[str]:
        """
        Build command to delete a resource.

        Args:
            name: Resource name

        Returns:
            Command arguments list
        """
        pass

    @abstractmethod
    def parse_list_output(self, stdout: str) -> List[str]:
        """
        Parse command output to extract resource names.

        Args:
            stdout: Command output

        Returns:
            List of resource names
        """
        pass

    @abstractmethod
    async def create_resource_model(self, name: str, **kwargs) -> T:
        """
        Create the resource model after successful creation.

        Args:
            name: Resource name
            **kwargs: Additional arguments for model creation

        Returns:
            Resource model instance
        """
        pass

    @abstractmethod
    async def get_resource_model(self, name: str) -> Optional[T]:
        """
        Get the resource model for an existing resource.

        Args:
            name: Resource name

        Returns:
            Resource model instance or None if not found
        """
        pass
