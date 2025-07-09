import logging
from typing import List

from ...service.exceptions import GroupOperationError
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

    # === Group-Specific Operations ===

    async def create_group(
        self,
        group_name: str,
        creator: str,
        members: List[str] | None = None,
    ) -> GroupModel:
        """
        Create a new MinIO group with complete setup including members, policies, and shared workspace.

        This method performs a comprehensive group creation workflow:
        1. Validates the group name format
        2. Verifies that all intended members exist as users
        3. Creates the group in MinIO with initial membership
        4. Creates and attaches a default group policy with shared workspace access
        5. Sets up the group's shared directory structure
        6. Creates a welcome file with workspace instructions

        The creator (admin) is automatically added to the group if not already in the members list.
        All members must exist as users before the group can be created.

        The group will have access to:
        - Shared workspace directory: `s3a://bucket/groups-general-warehouse/{group_name}/`
        - Subdirectories: shared/, datasets/, projects/

        Args:
            group_name: The name for the new group (must be valid per MinIO requirements)
            creator: Username of the user creating the group (automatically becomes a member)
            members: Optional list of usernames to add to the group (creator included automatically)
        """
        async with self.operation_context("create_group"):

            # Check if group already exists
            if await self.resource_exists(group_name):
                raise GroupOperationError(f"Group {group_name} already exists")

            # Create group with initial members (MinIO requires at least one member)
            if members is None:
                members = []

            # Ensure creator is included in members
            if creator not in members:
                members.append(creator)

            # Verify all members exist before creating group
            for member in members:
                if not await self.user_manager.resource_exists(member):
                    raise GroupOperationError(f"User {member} does not exist")

            # Create the group
            cmd_args = self._command_builder.build_group_command(
                GroupAction.ADD, group_name, members
            )
            result = await self._executor._execute_command(cmd_args)
            if not result.success:
                raise GroupOperationError(f"Failed to create group: {result.stderr}")

            # Create and attach group policy
            try:
                policy_model = await self.policy_manager.create_group_policy(group_name)
                await self.policy_manager.attach_policy_to_group(
                    policy_model.policy_name, group_name
                )
            except Exception as e:
                # Clean up policy if attachment fails
                try:
                    await self.policy_manager.delete_group_policy(group_name)
                    await self.delete_resource(group_name)
                except Exception as cleanup_error:
                    logger.warning(f"Failed to clean up policy after attachment failure: {cleanup_error}")
                raise GroupOperationError(f"Failed to attach policy to group: {e}")

            # Create group shared directory structure
            await self._create_group_shared_directory(group_name)

            # Return domain model
            group_model = GroupModel(
                group_name=group_name,
                members=members,
                policy_name=policy_model.policy_name,
            )

            logger.info(
                f"Successfully created real MinIO group {group_name} with policy {policy_model.policy_name} and admin structure"
            )
            return group_model

    # Private helper methods

    async def _create_group_shared_directory(self, group_name: str) -> None:
        """Create group shared directory structure similar to user home directory."""
        bucket_name = self.config.default_bucket

        # Ensure bucket exists
        if not await self.client.bucket_exists(bucket_name):
            await self.client.create_bucket(bucket_name)

        # Create group directory structure
        await self._create_group_directory_structure(group_name, bucket_name)
        await self._create_group_welcome_file(group_name, bucket_name)

    async def _create_group_directory_structure(
        self, group_name: str, bucket_name: str
    ) -> None:
        """Create the group's shared directory structure."""
        group_paths = [
            f"{self.groups_general_warehouse_prefix}/{group_name}/",
            f"{self.groups_general_warehouse_prefix}/{group_name}/shared/",
            f"{self.groups_general_warehouse_prefix}/{group_name}/datasets/",
            f"{self.groups_general_warehouse_prefix}/{group_name}/projects/",
        ]

        # Create directory markers
        for path in group_paths:
            # Create directory marker
            marker_key = f"{path}.keep"
            await self.client.put_object(
                bucket_name, marker_key, b"Group directory marker"
            )

    async def _create_group_welcome_file(
        self, group_name: str, bucket_name: str
    ) -> None:
        """Create a welcome file for the new group."""
        welcome_content = f"""Welcome to the {group_name} group shared workspace!

This is a shared space for all members of the {group_name} group.
All group members have full read/write access to this space.

Directory structure:
- shared/: General shared files and documents
- datasets/: Shared datasets for the group  
- projects/: Collaborative project workspaces

Happy collaborating!
""".encode()

        welcome_key = f"{self.groups_general_warehouse_prefix}/{group_name}/README.txt"
        await self.client.put_object(bucket_name, welcome_key, welcome_content)

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
