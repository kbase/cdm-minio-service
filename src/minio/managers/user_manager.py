import json
import logging
from typing import List

from ..core.minio_client import MinIOClient
from ..models.command import UserAction
from ..models.minio_config import MinIOConfig
from ..models.user import UserModel
from ..utils.validators import validate_username
from .policy_manager import TargetType
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE = "user"


class UserManager(ResourceManager[UserModel]):
    """UserManager for basic user operations with patterns and generic CRUD."""

    def __init__(self, client: MinIOClient, config: MinIOConfig) -> None:
        super().__init__(client, config)
        self.users_general_warehouse_prefix = config.users_general_warehouse_prefix
        self.users_sql_warehouse_prefix = config.users_sql_warehouse_prefix

        # Lazy initialization of dependent managers to avoid circular imports
        self._policy_manager = None
        self._group_manager = None

    @property
    def policy_manager(self):
        """
        Get the PolicyManager instance for policy-related operations.

        This property provides lazy initialization of the PolicyManager to avoid
        circular import dependencies. The PolicyManager handles all user policy
        creation, management, and attachment operations.

        Returns:
            PolicyManager: Initialized PolicyManager instance for policy operations
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
        circular import dependencies. The GroupManager handles user-group membership
        operations and group policy management.

        Returns:
            GroupManager: Initialized GroupManager instance for group operations
        """
        if self._group_manager is None:
            from .group_manager import GroupManager

            self._group_manager = GroupManager(self.client, self.config)
        return self._group_manager

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a username."""
        return validate_username(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if user exists."""
        return self._command_builder.build_user_command(UserAction.INFO, name)

    def _build_list_command(self) -> List[str]:
        """Build command to list all users."""
        return self._command_builder.build_user_list_command(json_format=True)

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a user."""
        return self._command_builder.build_user_command(UserAction.REMOVE, name)

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse user list command output."""
        try:
            # The mc command outputs a stream of JSON objects, one per line
            json_lines = stdout.strip().split("\n")
            users_data = [json.loads(line) for line in json_lines if line]

            # Extract the accessKey which corresponds to the username
            usernames = [
                user["accessKey"] for user in users_data if "accessKey" in user
            ]
            return usernames
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON from list_users command: {e}")
            return []

    # === Pre/Post Delete Cleanup Overrides ===

    async def _pre_delete_cleanup(self, name: str, force: bool = False) -> None:
        """Clean up user resources before deletion."""
        policy_name = self.policy_manager.get_policy_name(TargetType.USER, name)

        # Clean up user policy
        await self.policy_manager.detach_policy_from_user(policy_name, name)
        await self.policy_manager.delete_user_policy(name)

    async def _post_delete_cleanup(self, name: str) -> None:
        """Clean up user resources after deletion."""
        # Delete user home directory
        await self._delete_user_home_directory(name)

    # PRIVATE HELPER METHODS
    async def _delete_user_home_directory(self, username: str) -> None:
        """Delete user home directories and all contents (both SQL and general warehouse)."""
        bucket_name = self.config.default_bucket

        # Delete both warehouse directories
        prefixes = [
            f"{self.users_general_warehouse_prefix}/{username}/",
            f"{self.users_sql_warehouse_prefix}/{username}/",
        ]

        for user_prefix in prefixes:
            # List all objects in user directory
            objects = await self.client.list_objects(bucket_name, user_prefix)

            # Delete objects
            for obj_key in objects:
                await self.client.delete_object(bucket_name, obj_key)

            logger.info(f"Deleted {len(objects)} objects from {user_prefix}")
