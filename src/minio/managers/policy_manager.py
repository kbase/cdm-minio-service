import logging
import re
from typing import List

from ...service.arg_checkers import not_falsy
from ..core.minio_client import MinIOClient
from ..models.command import PolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import PolicyModel
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
