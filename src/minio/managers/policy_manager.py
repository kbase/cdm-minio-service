import json
import logging
import re
import tempfile
from enum import Enum
from pathlib import Path
from typing import List

from ...service.arg_checkers import not_falsy
from ...service.exceptions import PolicyOperationError
from ..core.minio_client import MinIOClient
from ..models.command import PolicyAction as CommandPolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
)
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

# MinIO built-in policies
RESERVED_POLICIES = {
    "readonly",
    "readwrite",
    "writeonly",
    "diagnostics",
    "public",
    "consoleAdmin",
}
RESOURCE_TYPE = "policy"

# Permission level to action mappings
PERMISSION_LEVEL_ACTIONS = {
    PolicyPermissionLevel.READ: [
        PolicyAction.GET_OBJECT,
    ],
    PolicyPermissionLevel.WRITE: [
        PolicyAction.GET_OBJECT,
        PolicyAction.PUT_OBJECT,
        PolicyAction.DELETE_OBJECT,
    ],
    PolicyPermissionLevel.ADMIN: [PolicyAction.ALL_ACTIONS],
}


class TargetType(str, Enum):
    """Target types for policy operations."""

    USER = "user"
    GROUP = "group"


class PolicyManager(ResourceManager[PolicyModel]):
    """
    PolicyManager for core policy CRUD operations with generic CRUD patterns.

    This manager handles:
    - Creating, reading, updating, deleting policies
    - Policy attachment/detachment to users/groups
    - Low-level policy manipulation and validation
    - Policy templates and document generation
    """

    def __init__(self, client: MinIOClient, config: MinIOConfig) -> None:
        super().__init__(client, config)

    # === ResourceManager Abstract Method Implementations ===

    def _get_resource_type(self) -> str:
        """Get the resource type name."""
        return RESOURCE_TYPE

    def _validate_resource_name(self, name: str) -> str:
        """Validate and normalize a policy name."""
        name = not_falsy(name, "Policy name")

        # Basic policy name validation
        name = name.strip()
        if len(name) < 2:
            raise ValueError("Policy name must be at least 2 characters long")
        if len(name) > 128:
            raise ValueError("Policy name must be at most 128 characters long")

        # Must contain only alphanumeric characters, periods, hyphens, and underscores
        if not re.match(r"^[a-zA-Z0-9._-]+$", name):
            raise ValueError(
                "Policy name can only contain alphanumeric characters, "
                "periods (.), hyphens (-), and underscores (_)"
            )

        # Cannot start with a period or hyphen
        if name[0] in ".":
            raise ValueError("Policy name cannot start with a period")

        # Check for reserved policy names (MinIO built-in policies)
        if name in RESERVED_POLICIES:
            raise ValueError(f"'{name}' is a reserved policy name")

        # Avoid names that could be confused with system policies
        if name.startswith("arn:"):
            raise ValueError("Policy name cannot start with 'arn:'")

        return name

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if policy exists."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.INFO, name
        )

    def _build_list_command(self) -> List[str]:
        """Build command to list all policies."""
        return self._command_builder.build_policy_command(CommandPolicyAction.LIST)

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a policy."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.DELETE, name
        )

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse policy list command output."""
        # Parse policy names from the output
        policy_names = [
            line.strip()
            for line in stdout.split("\n")
            if line.strip() and not line.startswith("Policy")
        ]
        return policy_names

    # === CORE POLICY CRUD OPERATIONS ===

    async def create_policy(
        self, target_type: TargetType, target_name: str
    ) -> PolicyModel:
        """
        Create a default policy for a user or group with standard permissions.

        This method generates a new policy with default access permissions based on the target type.
        For users, it grants access to both SQL and general warehouse paths. For groups, it grants
        access to the group's shared workspace.

        Args:
            target_type: The type of target (USER or GROUP) for the policy
            target_name: The username or group name to create the policy for
        """
        async with self.operation_context("create_policy"):
            policy_name = self.get_policy_name(target_type, target_name)

            policy_model = self._build_default_policy(
                target_type, target_name, policy_name
            )

            await self._create_minio_policy(policy_model)
            logger.info(f"Created {target_type.value} policy: {policy_name}")
            return policy_model

    async def get_policy(
        self, target_type: TargetType, target_name: str
    ) -> PolicyModel:
        """
        Retrieve the existing policy for a user or group from MinIO.

        This method loads the complete policy document including all statements,
        permissions, and conditions from the MinIO server.

        Args:
            target_type: The type of target (USER or GROUP) to get the policy for
            target_name: The username or group name to retrieve the policy for
        """
        async with self.operation_context("get_policy"):
            policy_name = self.get_policy_name(target_type, target_name)
            return await self._load_minio_policy(policy_name)

    async def update_policy(self, policy_model: PolicyModel) -> PolicyModel:
        """
        Update an existing policy in MinIO with new permissions or statements.

        This method handles the complex process of updating policies by:
        1. Detaching the policy from its current targets
        2. Deleting the old policy
        3. Creating the updated policy
        4. Re-attaching the policy to its targets

        Args:
            policy_model: The updated policy model to save to MinIO
        """
        async with self.operation_context("update_policy"):
            await self._update_minio_policy(policy_model)
            logger.info(f"Updated policy: {policy_model.policy_name}")
            return policy_model

    async def delete_policy(self, target_type: TargetType, target_name: str) -> None:
        """
        Delete a user's or group's policy from MinIO.

        This method permanently removes the policy from MinIO. The policy will be
        automatically detached from any users or groups before deletion.

        Args:
            target_type: The type of target (USER or GROUP) to delete the policy for
            target_name: The username or group name whose policy should be deleted
        """
        async with self.operation_context("delete_policy"):
            policy_name = self.get_policy_name(target_type, target_name)

            success = await self.delete_resource(policy_name)
            if not success:
                raise PolicyOperationError(f"Failed to delete policy: {policy_name}")

            logger.info(f"Deleted {target_type.value} policy: {policy_name}")

    # === CONVENIENCE METHODS FOR USER/GROUP POLICIES ===

    async def create_user_policy(self, username: str) -> PolicyModel:
        """Create a default policy for a user."""
        return await self.create_policy(TargetType.USER, username)

    async def create_group_policy(self, group_name: str) -> PolicyModel:
        """Create a default policy for a group."""
        return await self.create_policy(TargetType.GROUP, group_name)

    async def get_user_policy(self, username: str) -> PolicyModel:
        """Retrieve the existing policy for a specific user."""
        return await self.get_policy(TargetType.USER, username)

    async def get_group_policy(self, group_name: str) -> PolicyModel:
        """Retrieve the existing policy for a specific group."""
        return await self.get_policy(TargetType.GROUP, group_name)

    # === POLICY ATTACHMENT OPERATIONS ===
    async def attach_policy_to_user(self, policy_name: str, username: str) -> None:
        """
        Attach an existing policy to a user, granting them the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            username: The username to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, TargetType.USER, username, attach=True
        )

    async def detach_policy_from_user(self, policy_name: str, username: str) -> None:
        """
        Detach a policy from a user, removing the policy's permissions from the user.

        Args:
            policy_name: The name of the policy to detach
            username: The username to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, TargetType.USER, username, attach=False
        )

    async def attach_policy_to_group(self, policy_name: str, group_name: str) -> None:
        """
        Attach an existing policy to a group, granting all group members the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            group_name: The group name to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, TargetType.GROUP, group_name, attach=True
        )

    async def detach_policy_from_group(self, policy_name: str, group_name: str) -> None:
        """
        Detach a policy from a group, removing the policy's permissions from all group members.

        Args:
            policy_name: The name of the policy to detach
            group_name: The group name to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, TargetType.GROUP, group_name, attach=False
        )

    async def _attach_detach_policy(
        self, policy_name: str, target_type: TargetType, target_name: str, attach: bool
    ) -> None:
        """Generic method to attach or detach a policy to/from a user or group."""
        operation = "attach" if attach else "detach"
        operation_context = f"{operation}_policy_to_{target_type.value}"

        async with self.operation_context(operation_context):
            if attach:
                cmd_args = self._command_builder.build_policy_attach_command(
                    policy_name, target_type.value, target_name
                )
            else:
                cmd_args = self._command_builder.build_policy_detach_command(
                    policy_name, target_type.value, target_name
                )

            result = await self._executor._execute_command(cmd_args)

            if not result.success:
                raise PolicyOperationError(
                    f"Failed to {operation} policy {policy_name} {'to' if attach else 'from'} {target_type.value} {target_name}: {result.stderr}"
                )
            logger.info(
                f"{'Attached' if attach else 'Detached'} policy {policy_name} {'to' if attach else 'from'} {target_type.value} {target_name}"
            )

    # === POLICY DOCUMENT MANIPULATION ===

    def add_path_access_to_policy(
        self,
        policy_model: PolicyModel,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> None:
        """
        Add access permissions for a specific path to an existing policy model.

        Args:
            policy_model: The policy model to modify (modified in-place)
            path: The S3 path to grant access to (e.g., "s3a://bucket/path/to/data")
            permission_level: The level of access to grant (READ, WRITE, or ADMIN)

        Note:
            This method only modifies the policy model in memory. Call update_policy()
            to persist the changes to MinIO.
        """
        clean_path = self._normalize_path(path)

        self._add_path_to_list_bucket_statement(policy_model, clean_path)
        self._add_object_level_statement(policy_model, clean_path, permission_level)

    def _normalize_path(self, path: str) -> str:
        """Convert S3 path to bucket-relative path."""

        if not path.startswith(("s3://", "s3a://")):
            raise PolicyOperationError(
                f"Invalid S3 path format: {path}. Must start with s3:// or s3a://"
            )

        # Extract bucket and path from S3 URL
        path_without_scheme = re.sub(r"^s3a?://", "", path)
        path_parts = path_without_scheme.split("/", 1)

        if not path_parts:
            raise PolicyOperationError(f"Invalid S3 path format: {path}")

        bucket_in_path = path_parts[0]

        # Validate bucket matches our configuration
        # TODO: support multiple buckets in the future
        if bucket_in_path != self.config.default_bucket:
            raise PolicyOperationError(
                f"Path bucket '{bucket_in_path}' does not match configured bucket '{self.config.default_bucket}'"
            )

        # Return the path part (everything after bucket)
        if len(path_parts) <= 1:
            raise PolicyOperationError(
                f"S3 path must include a path component after bucket: {path}"
            )

        return path_parts[1]

    def _add_path_to_list_bucket_statement(
        self, policy_model: PolicyModel, clean_path: str
    ) -> None:
        """Add path prefixes to existing ListBucket statement."""
        list_bucket_stmt = self._find_list_bucket_statement(policy_model)

        if not list_bucket_stmt:
            return

        existing_prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]  # type: ignore
        new_prefixes = [f"{clean_path}/*", f"{clean_path}"]

        for prefix in new_prefixes:
            if prefix not in existing_prefixes:
                existing_prefixes.append(prefix)

    def _find_list_bucket_statement(
        self, policy_model: PolicyModel
    ) -> PolicyStatement | None:
        """Find the ListBucket statement with prefix conditions."""
        for stmt in policy_model.policy_document.statement:
            if (
                PolicyAction.LIST_BUCKET in stmt.action
                and stmt.condition
                and "StringLike" in stmt.condition
                and "s3:prefix" in stmt.condition["StringLike"]
            ):
                return stmt
        return None

    def _add_object_level_statement(
        self,
        policy_model: PolicyModel,
        clean_path: str,
        permission_level: PolicyPermissionLevel,
    ) -> None:
        """Add object-level permissions statement for the path."""
        actions = PERMISSION_LEVEL_ACTIONS[permission_level]

        new_statement = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=actions,
            resource=[f"arn:aws:s3:::{self.config.default_bucket}/{clean_path}/*"],
            condition=None,
            principal=None,
        )
        # Only add if an equivalent statement doesn't already exist
        if new_statement not in policy_model.policy_document.statement:
            policy_model.policy_document.statement.append(new_statement)

    # === LISTING AND UTILITY METHODS ===

    def get_policy_name(self, target_type: TargetType, target_name: str) -> str:
        """
        Generate a standardized policy name for a user or group.

        This method creates consistent policy names following the pattern:
        - User policies: "user-policy-{username}"
        - Group policies: "group-policy-{groupname}"

        Args:
            target_type: The type of target (USER or GROUP)
            target_name: The username or group name

        Returns:
            str: The standardized policy name
        """
        return f"{target_type.value}-policy-{target_name}"

    # === PRIVATE HELPER METHODS ===

    def _build_default_policy(
        self, target_type: TargetType, target_name: str, policy_name: str
    ) -> PolicyModel:
        """Build default policy for user or group."""
        resource_paths = self._get_target_resource_paths(target_type, target_name)
        statements = self._create_policy_statements(resource_paths)

        return PolicyModel(
            policy_name=policy_name,
            policy_document=PolicyDocument(statement=statements),
        )

    def _get_target_resource_paths(
        self, target_type: TargetType, target_name: str
    ) -> list[str]:
        """Get resource paths for a target based on its type."""
        if target_type == TargetType.USER:
            return [
                f"{self.config.users_sql_warehouse_prefix}/{target_name}",
                f"{self.config.users_general_warehouse_prefix}/{target_name}",
            ]
        elif target_type == TargetType.GROUP:
            return [f"{self.config.groups_general_warehouse_prefix}/{target_name}"]
        else:
            raise PolicyOperationError(f"Invalid target type: {target_type}")

    def _create_policy_statements(
        self, resource_paths: list[str]
    ) -> list[PolicyStatement]:
        """Create all required policy statements for S3 access."""
        return [
            self._create_list_all_buckets_statement(),
            self._create_bucket_location_statement(),
            self._create_list_bucket_statement(resource_paths),
            self._create_object_operations_statement(resource_paths),
        ]

    def _create_list_all_buckets_statement(self) -> PolicyStatement:
        """Create statement for listing all buckets (required for MinIO users to see buckets in the UI)."""
        return PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=[PolicyAction.LIST_ALL_MY_BUCKETS],
            resource=["*"],
            condition=None,
            principal=None,
        )

    def _create_bucket_location_statement(self) -> PolicyStatement:
        """Create statement for getting bucket location (required for MinIO users to see buckets in the UI)."""
        return PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=[PolicyAction.GET_BUCKET_LOCATION],
            resource=[f"arn:aws:s3:::{self.config.default_bucket}"],
            condition=None,
            principal=None,
        )

    def _create_list_bucket_statement(
        self, resource_paths: list[str]
    ) -> PolicyStatement:
        """Create statement for listing bucket contents with path restrictions."""
        prefix_conditions = []
        for path in resource_paths:
            prefix_conditions.extend([f"{path}/*", f"{path}"])

        return PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=[PolicyAction.LIST_BUCKET],
            resource=[f"arn:aws:s3:::{self.config.default_bucket}"],
            condition={"StringLike": {"s3:prefix": prefix_conditions}},
            principal=None,
        )

    def _create_object_operations_statement(
        self, resource_paths: list[str]
    ) -> PolicyStatement:
        """Create statement for object-level operations (get, put, delete)."""
        object_resources = [
            f"arn:aws:s3:::{self.config.default_bucket}/{path}/*"
            for path in resource_paths
        ]

        return PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=[
                PolicyAction.GET_OBJECT,
                PolicyAction.PUT_OBJECT,
                PolicyAction.DELETE_OBJECT,
            ],
            resource=object_resources,
            condition=None,
            principal=None,
        )

    async def _create_minio_policy(self, policy_model: PolicyModel) -> None:
        """Create policy in MinIO with retry logic."""
        policy_json = policy_model.to_minio_policy_json()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as temp_file:
            temp_file.write(policy_json)
            temp_file_path = temp_file.name

        try:
            # Use command building pattern
            cmd_args = self._command_builder.build_policy_command(
                CommandPolicyAction.CREATE, policy_model.policy_name, temp_file_path
            )
            result = await self._executor._execute_command(cmd_args)

            if not result.success:
                raise PolicyOperationError(
                    f"Failed to create MinIO policy: {result.stderr}"
                )
        finally:
            # Clean up temporary file
            try:
                Path(temp_file_path).unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary policy file: {e}")

    async def _update_minio_policy(self, policy_model: PolicyModel) -> None:
        """Update a policy in MinIO by handling attachments properly."""
        policy_name = policy_model.policy_name

        # For user policies, detach from the specific user first
        if policy_name.startswith(f"{TargetType.USER.value}-policy-"):
            username = policy_name.replace(f"{TargetType.USER.value}-policy-", "")
            logger.info(
                f"Detected user policy {policy_name} for user {username}, detaching first"
            )
            await self.detach_policy_from_user(policy_name, username)
            logger.info(f"Successfully detached {policy_name} from user {username}")

        # For group policies, detach from the specific group first
        elif policy_name.startswith(f"{TargetType.GROUP.value}-policy-"):
            group_name = policy_name.replace(f"{TargetType.GROUP.value}-policy-", "")
            logger.info(
                f"Detected group policy {policy_name} for group {group_name}, detaching first"
            )
            await self.detach_policy_from_group(policy_name, group_name)
            logger.info(f"Successfully detached {policy_name} from group {group_name}")

        # Now delete and recreate the policy
        logger.info(f"Deleting policy {policy_name}")
        await self.delete_resource(policy_name)
        logger.info(f"Creating updated policy {policy_name}")
        await self._create_minio_policy(policy_model)

        # Reattach to the specific user/group
        if policy_name.startswith(f"{TargetType.USER.value}-policy-"):
            username = policy_name.replace(f"{TargetType.USER.value}-policy-", "")
            await self.attach_policy_to_user(policy_name, username)
            logger.info(f"Reattached {policy_name} to user {username}")

        elif policy_name.startswith(f"{TargetType.GROUP.value}-policy-"):
            group_name = policy_name.replace(f"{TargetType.GROUP.value}-policy-", "")
            await self.attach_policy_to_group(policy_name, group_name)
            logger.info(f"Reattached {policy_name} to group {group_name}")

    async def _load_minio_policy(self, policy_name: str) -> PolicyModel:
        """Load a policy from MinIO using the command executor."""
        # Get policy info from MinIO
        cmd_args = self._command_builder.build_policy_command(
            CommandPolicyAction.INFO, policy_name
        )
        result = await self._executor._execute_command(cmd_args)
        if not result.success:
            raise PolicyOperationError(f"Failed to get policy info: {result.stderr}")

        policy_data = json.loads(result.stdout)

        # Extract the actual policy from MinIO response
        policy_json = policy_data.get("Policy", policy_data)

        # Create PolicyDocument from the policy JSON
        statements = []
        for stmt_data in policy_json.get("Statement", []):
            actions = []
            for action in stmt_data.get("Action", []):
                try:
                    matching_action = next(
                        policy_action
                        for policy_action in PolicyAction
                        if policy_action.value == action
                    )
                    actions.append(matching_action)
                except StopIteration:
                    actions.append(action)

            statement = PolicyStatement(
                effect=(
                    PolicyEffect.ALLOW
                    if stmt_data.get("Effect") == "Allow"
                    else PolicyEffect.DENY
                ),
                action=actions,
                resource=stmt_data.get("Resource", []),
                condition=stmt_data.get("Condition"),
                principal=stmt_data.get("Principal"),
            )
            statements.append(statement)

        policy_document = PolicyDocument(statement=statements)

        return PolicyModel(
            policy_name=policy_name,
            policy_document=policy_document,
        )
