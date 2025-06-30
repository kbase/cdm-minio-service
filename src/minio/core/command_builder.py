"""Command builders for MinIO MC operations."""

from typing import List

from ..models.command import AdminCommand


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