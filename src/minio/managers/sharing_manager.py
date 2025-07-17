"""
Sharing Manager for high-level data sharing workflows.

This manager orchestrates sharing operations by coordinating between
PolicyManager, UserManager, GroupManager, and PermissionService to provide
a clean, high-level API for data sharing.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List

from ..core.minio_client import MinIOClient
from ..models.minio_config import MinIOConfig
from .policy_manager import TargetType

logger = logging.getLogger(__name__)


class SharingOperation(Enum):
    """Enumeration for sharing operations."""

    ADD = "add"
    REMOVE = "remove"


@dataclass
class SharingResult:
    """Result of a sharing operation."""

    path: str
    shared_with_users: List[str] = field(default_factory=list)
    shared_with_groups: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    failed_users: List[str] = field(default_factory=list)
    failed_groups: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_success(self, target_type: TargetType, name: str) -> None:
        """Add a successful sharing target."""
        if target_type == TargetType.USER:
            self.shared_with_users.append(name)
        else:
            self.shared_with_groups.append(name)

    def add_failure(self, target_type: TargetType, name: str, error: str) -> None:
        """Add a failed sharing target."""
        self.errors.append(f"Error sharing with {target_type.value} {name}: {error}")
        if target_type == TargetType.USER:
            self.failed_users.append(name)
        else:
            self.failed_groups.append(name)

    @property
    def success_count(self) -> int:
        """Total number of successful shares."""
        return len(self.shared_with_users) + len(self.shared_with_groups)

    @property
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return bool(self.errors)


@dataclass
class UnsharingResult:
    """Result of an unsharing operation."""

    path: str
    unshared_from_users: List[str] = field(default_factory=list)
    unshared_from_groups: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    failed_users: List[str] = field(default_factory=list)
    failed_groups: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_success(self, target_type: TargetType, name: str) -> None:
        """Add a successful unsharing target."""
        if target_type == TargetType.USER:
            self.unshared_from_users.append(name)
        else:
            self.unshared_from_groups.append(name)

    def add_failure(self, target_type: TargetType, name: str, error: str) -> None:
        """Add a failed unsharing target."""
        self.errors.append(f"Error unsharing from {target_type.value} {name}: {error}")
        if target_type == TargetType.USER:
            self.failed_users.append(name)
        else:
            self.failed_groups.append(name)

    @property
    def success_count(self) -> int:
        """Total number of successful unshares."""
        return len(self.unshared_from_users) + len(self.unshared_from_groups)

    @property
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return bool(self.errors)


class SharingManager:
    """
    SharingManager for high-level data sharing workflows.
    """

    def __init__(self, client: MinIOClient, config: MinIOConfig):
        """
        Initialize SharingManager with dependency injection.

        Args:
            client: MinIO client instance
            config: MinIO configuration
        """
        self.client = client
        self.config = config

        # Lazy initialization of dependent managers to avoid circular imports
        self._policy_manager = None
        self._user_manager = None
        self._group_manager = None

    @property
    def user_manager(self):
        """
        Get the UserManager instance for user-related operations.

        This property provides lazy initialization of the UserManager to avoid
        circular import dependencies. The UserManager is used for user validation
        and authorization checks during sharing operations.

        Returns:
            UserManager: Initialized UserManager instance
        """
        if self._user_manager is None:
            from .user_manager import UserManager

            self._user_manager = UserManager(self.client, self.config)
        return self._user_manager

    @property
    def policy_manager(self):
        """
        Get the PolicyManager instance for policy-related operations.

        This property provides lazy initialization of the PolicyManager to avoid
        circular import dependencies. The PolicyManager handles all low-level
        policy manipulation including adding/removing path access and updating policies.

        Returns:
            PolicyManager: Initialized PolicyManager instance
        """
        if self._policy_manager is None:
            from .policy_manager import PolicyManager

            self._policy_manager = PolicyManager(self.client, self.config)
        return self._policy_manager

    @property
    def group_manager(self):
        """
        Get the GroupManager instance for group-related operations.

        This property provides lazy initialization of the GroupManager to avoid
        circular import dependencies. The GroupManager is used for group validation
        and policy management during sharing operations.

        Returns:
            GroupManager: Initialized GroupManager instance
        """
        if self._group_manager is None:
            from .group_manager import GroupManager

            self._group_manager = GroupManager(self.client, self.config)
        return self._group_manager
