import logging
import re
import tempfile
from enum import Enum
from pathlib import Path
from typing import List

from ...service.arg_checkers import not_falsy
from ...service.exceptions import PolicyOperationError
from ..core.minio_client import MinIOClient
from ..models.command import PolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import PolicyDocument, PolicyEffect, PolicyModel, PolicyStatement
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
        return self._command_builder.build_policy_command(PolicyAction.INFO, name)

    def _build_list_command(self) -> List[str]:
        """Build command to list all policies."""
        return self._command_builder.build_policy_command(PolicyAction.LIST)

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a policy."""
        return self._command_builder.build_policy_command(PolicyAction.DELETE, name)

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
        """Create a default policy for a user or group."""
        async with self.operation_context("create_policy"):
            policy_name = self._get_policy_name(target_type, target_name)

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

    # === PRIVATE HELPER METHODS ===
    def _get_policy_name(self, target_type: TargetType, target_name: str) -> str:
        """Generate standardized policy name."""
        return f"{target_type.value}-policy-{target_name}"

    def _build_default_policy(
        self, target_type: TargetType, target_name: str, policy_name: str
    ) -> PolicyModel:
        """Build default policy for user or group."""
        if target_type == TargetType.USER:
            resource_path = f"{self.config.users_warehouse_prefix}/{target_name}"
        else:  # GROUP
            resource_path = f"{self.config.groups_warehouse_prefix}/{target_name}"

        policy_doc = PolicyDocument(
            statement=[
                PolicyStatement(
                    effect=PolicyEffect.ALLOW,
                    action=[
                        PolicyAction.GET_OBJECT,
                        PolicyAction.PUT_OBJECT,
                        PolicyAction.DELETE_OBJECT,
                        PolicyAction.LIST_BUCKET,
                    ],
                    resource=[
                        f"arn:aws:s3:::{self.config.default_bucket}/{resource_path}/*",
                        f"arn:aws:s3:::{self.config.default_bucket}",
                    ],
                    condition=None,
                    principal=None,
                )
            ]
        )

        return PolicyModel(
            policy_name=policy_name,
            policy_document=policy_doc,
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
                PolicyAction.CREATE, policy_model.policy_name, temp_file_path
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
