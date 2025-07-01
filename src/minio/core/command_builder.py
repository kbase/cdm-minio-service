"""Command builders for MinIO MC operations."""

from typing import List, Optional

from ..models.command import AdminCommand, PolicyAction


class MinIOCommandBuilder:
    """Builder for constructing MinIO MC commands."""

    def __init__(self, alias: str) -> None:
        """Initialize with MinIO alias.

        Args:
            alias: The MinIO alias to use for commands
        """
        self.alias = alias

    def build_alias_set_command(
        self, endpoint: str, access_key: str, secret_key: str
    ) -> List[str]:
        """Build alias set command.

        Args:
            endpoint: MinIO endpoint URL
            access_key: Access key
            secret_key: Secret key

        Returns:
            Command arguments list
        """
        return [
            AdminCommand.ALIAS.value,
            "set",
            self.alias,
            endpoint,
            access_key,
            secret_key,
        ]

    # Policy Management Commands
    def build_policy_command(
        self,
        action: PolicyAction,
        policy_name: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> List[str]:
        """Build policy management command.

        Args:
            action: Policy action to perform
            policy_name: Policy name (required for all actions except LIST)
            file_path: Policy file path (required for CREATE action)

        Returns:
            Command arguments list

        Raises:
            ValueError: If policy_name is not provided for actions that require it
        """

        if action != PolicyAction.LIST and not policy_name:
            raise ValueError(f"Policy name is required for action: {action.value}")

        if action == PolicyAction.CREATE and not file_path:
            raise ValueError("File path is required for CREATE action")

        cmd = [
            "admin",
            AdminCommand.POLICY.value,
            action.value,
            self.alias,
        ]

        # Add policy_name for all actions except LIST
        if action != PolicyAction.LIST:
            cmd.append(policy_name)  # type: ignore

        # Add file_path for CREATE action
        if file_path and action == PolicyAction.CREATE:
            cmd.append(file_path)

        return cmd
