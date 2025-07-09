"""Command builders for MinIO MC operations."""

from typing import List, Optional

from ..models.command import AdminCommand, PolicyAction, UserAction
from ..utils.validators import validate_username


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

    # User Management Commands
    def build_user_command(
        self, action: UserAction, username: str, password: Optional[str] = None
    ) -> List[str]:
        """Build user management command.

        Args:
            action: User action to perform
            username: Username
            password: Password (for add/update actions)

        Returns:
            Command arguments list
        """
        validate_username(username)
        cmd = ["admin", AdminCommand.USER.value, action.value, self.alias, username]
        if password and action in (UserAction.ADD,):
            cmd.append(password)
        return cmd

    def build_user_list_command(self, json_format: bool = True) -> List[str]:
        """Build user list command.

        Args:
            json_format: Whether to use JSON format

        Returns:
            Command arguments list
        """
        cmd = ["admin", AdminCommand.USER.value, "list", self.alias]
        if json_format:
            cmd.append("--json")
        return cmd

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

    def _build_policy_target_command(
        self,
        action: PolicyAction,
        policy_name: str,
        target_type: str,
        target_name: str,
    ) -> List[str]:
        """Build policy attach/detach command.

        Args:
            action: Policy action (ATTACH or DETACH)
            policy_name: Policy name
            target_type: Target type (user or group)
            target_name: Target name

        Returns:
            Command arguments list
        """
        return [
            "admin",
            AdminCommand.POLICY.value,
            action.value,
            self.alias,
            policy_name,
            f"--{target_type}",
            target_name,
        ]

    def build_policy_attach_command(
        self,
        policy_name: str,
        target_type: str,
        target_name: str,
    ) -> List[str]:
        """Build policy attach command.

        Args:
            policy_name: Policy name
            target_type: Target type (user or group)
            target_name: Target name

        Returns:
            Command arguments list
        """
        return self._build_policy_target_command(
            PolicyAction.ATTACH, policy_name, target_type, target_name
        )

    def build_policy_detach_command(
        self,
        policy_name: str,
        target_type: str,
        target_name: str,
    ) -> List[str]:
        """Build policy detach command.

        Args:
            policy_name: Policy name
            target_type: Target type (user or group)
            target_name: Target name

        Returns:
            Command arguments list
        """
        return self._build_policy_target_command(
            PolicyAction.DETACH, policy_name, target_type, target_name
        )
