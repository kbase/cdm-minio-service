import logging
from typing import List

from ..core.minio_client import MinIOClient
from ..models.command import GroupAction
from ..models.group import GroupModel
from ..models.minio_config import MinIOConfig
from ..utils.validators import validate_group_name
from .policy_manager import TargetType
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE = "group"


class GroupManager(ResourceManager[GroupModel]):
    """GroupManager for basic group operations with patterns and generic CRUD."""

    def __init__(self, client: MinIOClient, config: MinIOConfig):
        super().__init__(client, config)
        self.groups_general_warehouse_prefix = config.groups_general_warehouse_prefix

        # Lazy initialization of dependent managers to avoid circular imports
        self._policy_manager = None
        self._user_manager = None

    @property
    def user_manager(self):
        """
        Get the UserManager instance for user-related operations.

        This property provides lazy initialization of the UserManager to avoid
        circular import dependencies. The UserManager is used for user validation
        and existence checks during group membership operations.

        Returns:
            UserManager: Initialized UserManager instance for user operations
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
        circular import dependencies. The PolicyManager handles all group policy
        creation, management, and attachment operations.

        Returns:
            PolicyManager: Initialized PolicyManager instance for policy operations
        """
        if self._policy_manager is None:
            from .policy_manager import PolicyManager

            self._policy_manager = PolicyManager(self.client, self.config)
        return self._policy_manager

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a group name."""
        return validate_group_name(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if group exists."""
        return self._command_builder.build_group_command(GroupAction.INFO, name)

    def _build_list_command(self) -> List[str]:
        """Build command to list all groups."""
        return self._command_builder.build_group_list_command()

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a group."""
        return self._command_builder.build_group_command(GroupAction.RM, name)

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse group list command output."""
        # Parse group names from output
        groups = []
        for line in stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and line != "Group":
                groups.append(line)
        return groups

    # === Pre/Post Delete Cleanup Overrides ===

    async def _pre_delete_cleanup(self, name: str, force: bool = False) -> None:
        """Clean up group resources before deletion."""
        # Clean up group policy
        policy_name = self.policy_manager.get_policy_name(TargetType.GROUP, name)
        try:
            await self.policy_manager.detach_policy_from_group(policy_name, name)
        except Exception as e:
            self.logger.warning(f"Failed to detach policy from group: {e}")

        try:
            await self.policy_manager.delete_group_policy(name)
        except Exception as e:
            self.logger.warning(f"Failed to delete group policy: {e}")

    async def _post_delete_cleanup(self, name: str) -> None:
        """Clean up group resources after deletion."""
        try:
            await self._delete_group_shared_directory(name)
        except Exception as e:
            self.logger.warning(f"Failed to delete group shared directory: {e}")

    # Private helper methods

    async def _delete_group_shared_directory(self, group_name: str) -> None:
        """Delete group shared directory and all contents."""
        bucket_name = self.config.default_bucket
        group_prefix = f"{self.groups_general_warehouse_prefix}/{group_name}/"

        try:
            # List all objects in group directory
            objects = await self.client.list_objects(bucket_name, group_prefix)

            # Delete objects
            for obj_key in objects:
                await self.client.delete_object(bucket_name, obj_key)
        except Exception as e:
            logger.warning(
                f"Failed to delete group shared directory for {group_name}: {e}"
            )
