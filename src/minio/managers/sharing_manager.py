"""
Sharing Manager for high-level data sharing workflows.

This manager orchestrates sharing operations by coordinating between
PolicyManager, UserManager, GroupManager, and PermissionService to provide
a clean, high-level API for data sharing.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Union

from ...service.exceptions import DataGovernanceError
from ..core.minio_client import MinIOClient
from ..models.minio_config import MinIOConfig
from ..models.policy import PolicyPermissionLevel
from ..utils.validators import validate_s3_path
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

    # === SHARING OPERATIONS ===

    async def share_path(
        self,
        path: str,
        requesting_user: str,
        with_users: Optional[List[str]] = None,
        with_groups: Optional[List[str]] = None,
    ) -> SharingResult:
        """
        Share an S3 path with specified users and/or groups, granting them access permissions.

        This method orchestrates the complete sharing workflow by:
        1. Validating the S3 path format and permissions
        2. Authorizing the requesting user has admin privileges for the path
        3. Adding path access to each target user's and group's policies
        4. Updating the policies in MinIO
        5. Collecting results and handling any errors gracefully

        The requesting user must have admin privileges for the path being shared.
        Target users and groups must already exist in the system before sharing.

        Args:
            path: The S3 path to share (e.g., "s3a://bucket/data/project1/")
            requesting_user: Username of the user requesting the share operation
            with_users: Optional list of usernames to grant access to the path
            with_groups: Optional list of group names to grant access to the path
        """
        logger.info(f"Starting share operation for path: {path}")

        # Validate and authorize
        await self._validate_and_authorize_request(path, requesting_user)

        # Initialize result
        result = SharingResult(path=path)

        await self._update_targets_sharing(
            SharingOperation.ADD, TargetType.USER, with_users or [], path, result
        )
        await self._update_targets_sharing(
            SharingOperation.ADD, TargetType.GROUP, with_groups or [], path, result
        )

        logger.info(f"Sharing completed for {path}: {result.success_count} targets")
        return result

    async def unshare_path(
        self,
        path: str,
        requesting_user: str,
        from_users: Optional[List[str]] = None,
        from_groups: Optional[List[str]] = None,
    ) -> UnsharingResult:
        """
        Remove access permissions for an S3 path from specified users and/or groups.

        This method orchestrates the complete unsharing workflow by:
        1. Validating the S3 path format and permissions
        2. Authorizing the requesting user has admin privileges for the path
        3. Removing path access from each target user's and group's policies
        4. Updating the policies in MinIO (only if changes were made)
        5. Collecting results and handling any errors gracefully

        The requesting user must have admin privileges for the path being unshared.
        If a target user or group doesn't have access to the path, the operation
        will be logged as a warning but won't cause the entire operation to fail.

        Args:
            path: The S3 path to remove access from (e.g., "s3a://bucket/data/project1/")
            requesting_user: Username of the user requesting the unshare operation
            from_users: Optional list of usernames to revoke access from
            from_groups: Optional list of group names to revoke access from
        """
        logger.info(f"Starting unshare operation for path: {path}")

        # Validate and authorize if user specified
        await self._validate_and_authorize_request(path, requesting_user)

        # Initialize result
        result = UnsharingResult(path=path)

        # Process unsharing concurrently
        await self._update_targets_sharing(
            SharingOperation.REMOVE, TargetType.USER, from_users or [], path, result
        )
        await self._update_targets_sharing(
            SharingOperation.REMOVE, TargetType.GROUP, from_groups or [], path, result
        )

        logger.info(f"Unsharing completed for {path}: {result.success_count} targets")
        return result

    # === UTILITY METHODS ===

    async def _validate_and_authorize_request(
        self, path: str, requesting_user: str
    ) -> None:
        """Validate path and authorize requesting user."""
        validate_s3_path(path)

        can_share = await self.user_manager.can_user_share_path(path, requesting_user)
        if not can_share:
            raise DataGovernanceError(
                f"User {requesting_user} does not have admin privileges for path {path}"
            )

    # === SHARING WORKFLOW HELPERS ===

    async def _update_targets_sharing(
        self,
        operation: SharingOperation,
        target_type: TargetType,
        names: List[str],
        path: str,
        result: Union[SharingResult, UnsharingResult],
    ) -> None:
        """Add or remove path sharing for multiple targets (users or groups)."""
        operation_verb = (
            "sharing with" if operation == SharingOperation.ADD else "unsharing from"
        )

        for name in names:
            try:
                await self._update_path_sharing(operation, target_type, name, path)
                result.add_success(target_type, name)
            except Exception as e:
                logger.error(
                    f"Unexpected error {operation_verb} {target_type.value} {name}: {e}"
                )
                result.add_failure(target_type, name, f"Unexpected error: {e}")

    async def _update_path_sharing(
        self,
        operation: SharingOperation,
        target_type: TargetType,
        target_name: str,
        path: str,
    ) -> None:
        """Add or remove path sharing by updating the appropriate policy."""
        policy_model = await self._get_policy(target_type, target_name)

        if not policy_model:
            raise DataGovernanceError(
                f"No policy found for {target_type.value} {target_name}. "
                f"User/group must be created first before sharing."
            )

        if operation == SharingOperation.ADD:
            updated_policy = self.policy_manager.add_path_access_to_policy(
                policy_model, path, PolicyPermissionLevel.WRITE
            )
            log_message = (
                f"Added path sharing: {path} to {target_type.value} {target_name}"
            )
            logger.debug(log_message)
        else:  # SharingOperation.REMOVE
            updated_policy = self.policy_manager.remove_path_access_from_policy(
                policy_model, path
            )
            log_message = (
                f"Removed path sharing: {path} from {target_type.value} {target_name}"
            )
            logger.info(log_message)

        await self.policy_manager.update_policy(updated_policy)

    async def _get_policy(self, target_type: TargetType, target_name: str):
        """Get existing policy for target."""
        if target_type == TargetType.USER:
            return await self.policy_manager.get_user_policy(target_name)
        else:
            return await self.policy_manager.get_group_policy(target_name)
