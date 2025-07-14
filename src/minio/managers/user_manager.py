import json
import logging
import secrets
import string
from typing import List, Optional

from ...service.exceptions import UserOperationError
from ..core.minio_client import MinIOClient
from ..models.command import UserAction
from ..models.minio_config import MinIOConfig
from ..models.user import UserModel
from ..utils.validators import validate_username
from .policy_manager import TargetType
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

RESOURCE_TYPE = "user"

# This is a global group that all users are automatically added to
# This group can be used to apply policies, share paths, etc. to all users
GLOBAL_USER_GROUP = "global-user-group"


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

    # CORE USER OPERATIONS

    async def create_user(
        self,
        username: str,
        password: Optional[str] = None,
    ) -> UserModel:
        """
        Create a new MinIO user with complete setup including credentials, policy, and workspace.

        This method performs a user creation workflow:
        1. Validates the username format
        2. Generates a secure password if not provided
        3. Creates or retrieves the user policy
        4. Creates the user account in MinIO if it doesn't exist
        5. Attaches the user policy if not already attached
        6. Sets up user home directories in both SQL and general warehouses
        7. Creates a welcome file with workspace instructions

        The user will receive access to:
        - Personal SQL warehouse directory: `s3a://bucket/users-sql-warehouse/{username}/`
        - Personal general warehouse directory: `s3a://bucket/users-general-warehouse/{username}/`
        - Subdirectories: data/, notebooks/, shared/

        Group memberships can be added later using separate group management endpoints.

        Args:
            username: The username for the new user (must be valid per MinIO requirements)
            password: Optional password for the user (auto-generated if not provided)

        Returns:
            UserModel: Complete user information including credentials and policy

        Raises:
            UserOperationError: If user creation fails or username is invalid
        """
        async with self.operation_context("create_user"):
            validate_username(username)
            if password is None:
                password = self._generate_secure_password()

            # Create user policy
            try:
                policy_model = await self.policy_manager.get_user_policy(username)
            except Exception as e:
                logger.warning(f"Failed to get user policy - creating new policy")
                policy_model = await self.policy_manager.create_user_policy(username)

            # Create the user
            if not await self.resource_exists(username):
                cmd_args = self._command_builder.build_user_command(
                    UserAction.ADD, username, password
                )
                result = await self._executor._execute_command(cmd_args)
                if not result.success:
                    raise UserOperationError(
                        f"Failed to create MinIO user: {result.stderr}"
                    )

            # Attach user policy only if not already attached
            if not await self.policy_manager.is_policy_attached_to_user(username):
                await self.policy_manager.attach_policy_to_user(
                    policy_model.policy_name, username
                )

            # Create user home directory structure
            await self._create_user_home_directory(username)
            home_paths = self._get_user_home_paths(username)

            if not await self.group_manager.resource_exists(GLOBAL_USER_GROUP):
                await self.group_manager.create_group(GLOBAL_USER_GROUP, username)
            await self.group_manager.add_user_to_group(username, GLOBAL_USER_GROUP)

            return UserModel(
                username=username,
                access_key=username,  # access key is always the username
                secret_key=password,
                home_paths=home_paths,
                groups=[],  # No groups assigned during creation
                user_policy=policy_model,
                group_policies=[],  # No group policies during creation
                total_policies=1,  # Just the user policy
                accessible_paths=home_paths,  # user home path is accessible via newly created policy
            )

    # PRIVATE HELPER METHODS
    def _generate_secure_password(self, length: int = 32) -> str:
        """Generate a secure password for MinIO users."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _get_user_home_paths(self, username: str) -> list[str]:
        """Get the user's primary home path (general warehouse) and SQL warehouse path."""
        return [
            f"s3a://{self.config.default_bucket}/{self.users_general_warehouse_prefix}/{username}/",
            f"s3a://{self.config.default_bucket}/{self.users_sql_warehouse_prefix}/{username}/",
        ]

    async def _create_user_home_directory(self, username: str) -> None:
        """Create user home directory structure with async patterns."""
        bucket_name = self.config.default_bucket

        # Ensure bucket exists
        if not await self.client.bucket_exists(bucket_name):
            await self.client.create_bucket(bucket_name)

        # Create directory structure and welcome file in parallel
        await self._create_directory_structure(username, bucket_name)
        await self._create_welcome_file(username, bucket_name)

    async def _create_directory_structure(
        self, username: str, bucket_name: str
    ) -> None:
        """Create the user's directory structure."""
        home_paths = [
            f"{self.users_sql_warehouse_prefix}/{username}/",
            f"{self.users_general_warehouse_prefix}/{username}/",
            f"{self.users_general_warehouse_prefix}/{username}/data/",
            f"{self.users_general_warehouse_prefix}/{username}/notebooks/",
            f"{self.users_general_warehouse_prefix}/{username}/shared/",
        ]

        # Create directory markers
        for path in home_paths:
            # Create directory marker
            marker_key = f"{path}.keep"
            await self.client.put_object(
                bucket_name, marker_key, b"User directory marker"
            )

    async def _create_welcome_file(self, username: str, bucket_name: str) -> None:
        """Create a welcome file for the new user."""
        welcome_content = f"""Welcome to your MinIO workspace, {username}!

This is your personal data directory. You have full read/write access to this space.

Directory structure:
- data/: Store your datasets here
- notebooks/: Store your Jupyter notebooks here  
- shared/: Files shared with you by other users

Happy data science!
""".encode()

        welcome_key = f"{self.users_general_warehouse_prefix}/{username}/README.txt"
        await self.client.put_object(bucket_name, welcome_key, welcome_content)

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
