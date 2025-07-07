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

    # === CONVENIENCE METHODS FOR USER/GROUP POLICIES ===

    async def create_user_policy(self, username: str) -> PolicyModel:
        """Create a default policy for a user."""
        return await self.create_policy(TargetType.USER, username)

    async def create_group_policy(self, group_name: str) -> PolicyModel:
        """Create a default policy for a group."""
        return await self.create_policy(TargetType.GROUP, group_name)

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
