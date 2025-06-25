"""
Modern MinIO Command Executor
Provides clean, async interface for MC CLI operations with proper error handling.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from ...service.exceptions import MinIOManagerError
from ..models.minio_config import MinIOConfig

logger = logging.getLogger(__name__)


class AdminCommand(Enum):
    """MinIO Admin command categories."""

    USER = "user"
    POLICY = "policy"
    GROUP = "group"
    ACCESSKEY = "accesskey"
    ALIAS = "alias"


class UserAction(Enum):
    """User management actions."""

    ADD = "add"
    REMOVE = "remove"
    LIST = "list"
    INFO = "info"
    ENABLE = "enable"
    DISABLE = "disable"


class PolicyAction(Enum):
    """Policy management actions."""

    CREATE = "create"
    REMOVE = "remove"
    LIST = "list"
    INFO = "info"
    ATTACH = "attach"
    DETACH = "detach"
    ENTITIES = "entities"


class GroupAction(Enum):
    """Group management actions."""

    ADD = "add"
    RM = "rm"
    LS = "ls"
    INFO = "info"
    ENABLE = "enable"
    DISABLE = "disable"


class AccessKeyAction(Enum):
    """Access key management actions."""

    CREATE = "create"
    LIST = "list"


@dataclass
class CommandResult:
    """Result of a MinIO command execution."""

    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str


@dataclass
class AccessKeyPair:
    """Access key pair result."""

    access_key: Optional[str]
    secret_key: Optional[str]

    @property
    def is_valid(self) -> bool:
        """Check if both keys are present."""
        return self.access_key is not None and self.secret_key is not None


class MinIOCommandExecutor:
    """Modern executor for MinIO MC CLI commands."""

    def __init__(self, config: MinIOConfig, alias: str = "minio_api") -> None:
        self.config = config
        self.alias = alias
        self._setup_complete = False
        self._mc_path = os.getenv("MC_PATH", "/usr/local/bin/mc")

    # ============ Setup and Configuration ============

    async def setup(self) -> None:
        """Initialize the command executor with MC alias setup."""
        if self._setup_complete:
            return

        try:
            # Small delay to ensure MinIO is ready
            await asyncio.sleep(1)

            # Get admin credentials from environment or use defaults
            admin_user = os.getenv("MINIO_ROOT_USER", "minio")
            admin_password = os.getenv("MINIO_ROOT_PASSWORD", "minio123")

            # Set up MC alias
            result = await self._execute_command(
                [
                    AdminCommand.ALIAS.value,
                    "set",
                    self.alias,
                    str(self.config.endpoint),
                    admin_user,
                    admin_password,
                ]
            )

            if not result.success:
                raise MinIOManagerError(
                    f"Failed to configure MinIO admin access: {result.stderr}"
                )

            logger.info(f"Successfully configured MC alias: {self.alias}")
            self._setup_complete = True

        except Exception as e:
            logger.error(f"Error setting up MC command executor: {e}")
            raise MinIOManagerError(f"Failed to initialize MinIO admin client: {e}")

    # ============ User Management ============

    async def create_user(self, username: str, password: str) -> CommandResult:
        """Create a MinIO user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.ADD.value,
                self.alias,
                username,
                password,
            ]
        )

    async def delete_user(self, username: str) -> CommandResult:
        """Delete a MinIO user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.REMOVE.value,
                self.alias,
                username,
            ]
        )

    async def get_user_info(self, username: str) -> CommandResult:
        """Get user information."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.INFO.value,
                self.alias,
                username,
            ]
        )

    async def list_users(self) -> CommandResult:
        """List all MinIO users in JSON format to avoid truncation."""
        await self.setup()
        return await self._execute_command(
            ["admin", AdminCommand.USER.value, UserAction.LIST.value, self.alias, "--json"]
        )

    async def user_exists(self, username: str) -> bool:
        """Check if a user exists by getting user info directly."""
        result = await self.get_user_info(username)
        return result.success

    async def enable_user(self, username: str) -> CommandResult:
        """Enable a user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.ENABLE.value,
                self.alias,
                username,
            ]
        )

    async def disable_user(self, username: str) -> CommandResult:
        """Disable a user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.DISABLE.value,
                self.alias,
                username,
            ]
        )

    async def update_user_password(
        self, username: str, new_password: str
    ) -> CommandResult:
        """Update a user's password."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.USER.value,
                UserAction.ADD.value,
                self.alias,
                username,
                new_password,
            ]
        )

    # ============ Policy Management ============

    async def create_policy(
        self, policy_name: str, policy_file_path: str
    ) -> CommandResult:
        """Create a policy from file."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.CREATE.value,
                self.alias,
                policy_name,
                policy_file_path,
            ]
        )

    async def delete_policy(self, policy_name: str) -> CommandResult:
        """Delete a policy."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.REMOVE.value,
                self.alias,
                policy_name,
            ]
        )

    async def get_policy_info(self, policy_name: str) -> CommandResult:
        """Get policy information/content."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.INFO.value,
                self.alias,
                policy_name,
            ]
        )

    async def list_policies(self) -> CommandResult:
        """List all policies."""
        await self.setup()
        return await self._execute_command(
            ["admin", AdminCommand.POLICY.value, PolicyAction.LIST.value, self.alias]
        )

    async def attach_policy_to_user(
        self, policy_name: str, username: str
    ) -> CommandResult:
        """Attach a policy to a user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.ATTACH.value,
                self.alias,
                policy_name,
                "--user",
                username,
            ]
        )

    async def detach_policy_from_user(
        self, policy_name: str, username: str
    ) -> CommandResult:
        """Detach a policy from a user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.DETACH.value,
                self.alias,
                policy_name,
                "--user",
                username,
            ]
        )

    async def attach_policy_to_group(
        self, policy_name: str, group_name: str
    ) -> CommandResult:
        """Attach a policy to a group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.ATTACH.value,
                self.alias,
                policy_name,
                "--group",
                group_name,
            ]
        )

    async def detach_policy_from_group(
        self, policy_name: str, group_name: str
    ) -> CommandResult:
        """Detach a policy from a group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.DETACH.value,
                self.alias,
                policy_name,
                "--group",
                group_name,
            ]
        )

    async def list_user_policies(self, username: str) -> CommandResult:
        """List policies attached to a specific user."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.ENTITIES.value,
                self.alias,
                "--user",
                username,
            ]
        )

    async def list_group_policies(self, group_name: str) -> CommandResult:
        """List policies attached to a specific group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.POLICY.value,
                PolicyAction.ENTITIES.value,
                self.alias,
                "--group",
                group_name,
            ]
        )

    # ============ Access Key Management ============

    async def create_access_key(self, username: str) -> AccessKeyPair:
        """Create an access key for a user and return AccessKeyPair."""
        await self.setup()
        result = await self._execute_command(
            [
                "admin",
                AdminCommand.ACCESSKEY.value,
                AccessKeyAction.CREATE.value,
                self.alias,
                username,
            ]
        )

        logger.debug(
            f"create_access_key result for {username}: success={result.success}"
        )
        logger.debug(f"create_access_key stdout: {result.stdout}")

        if not result.success:
            return AccessKeyPair(access_key=None, secret_key=None)

        return self._parse_access_key_output(result.stdout)

    async def list_access_keys(self, username: str) -> List[str]:
        """List access keys for a user."""
        await self.setup()
        result = await self._execute_command(
            [
                "admin",
                AdminCommand.ACCESSKEY.value,
                AccessKeyAction.LIST.value,
                self.alias,
                username,
            ]
        )

        if not result.success:
            return []

        return self._parse_access_keys_list(result.stdout)

    # ============ Group Management ============

    async def create_group(
        self, group_name: str, members: Optional[List[str]] = None
    ) -> CommandResult:
        """Create a MinIO group with optional initial members."""
        await self.setup()

        if not members:
            return self._create_empty_group_error(group_name)

        # Create group with initial members
        return await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.ADD.value,
                self.alias,
                group_name,
            ]
            + members
        )

    async def add_user_to_group(self, group_name: str, username: str) -> CommandResult:
        """Add a user to an existing group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.ADD.value,
                self.alias,
                group_name,
                username,
            ]
        )

    async def remove_user_from_group(
        self, group_name: str, username: str
    ) -> CommandResult:
        """Remove a user from a group by recreating the group without that user."""
        await self.setup()

        # Get current group members
        group_info_result = await self.get_group_info(group_name)
        if not group_info_result.success:
            return group_info_result

        # Parse and validate members
        current_members = self._parse_group_members(group_info_result.stdout)

        if username not in current_members:
            return self._create_user_not_in_group_error(username, group_name)

        current_members.remove(username)

        if not current_members:
            return self._create_cannot_remove_last_member_error(group_name)

        # Recreate group with remaining members
        return await self._recreate_group_with_members(group_name, current_members)

    async def list_groups(self) -> CommandResult:
        """List all groups."""
        await self.setup()
        return await self._execute_command(
            ["admin", AdminCommand.GROUP.value, GroupAction.LS.value, self.alias]
        )

    async def get_group_info(self, group_name: str) -> CommandResult:
        """Get detailed information about a group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.INFO.value,
                self.alias,
                group_name,
            ]
        )

    async def delete_group(self, group_name: str) -> CommandResult:
        """Delete a group, handling non-empty groups by clearing members first."""
        await self.setup()

        # Try direct deletion first
        result = await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.RM.value,
                self.alias,
                group_name,
            ]
        )

        # Handle non-empty group deletion
        if not result.success and "not empty" in result.stderr:
            return await self._handle_non_empty_group_deletion(group_name)

        return result

    async def enable_group(self, group_name: str) -> CommandResult:
        """Enable a group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.ENABLE.value,
                self.alias,
                group_name,
            ]
        )

    async def disable_group(self, group_name: str) -> CommandResult:
        """Disable a group."""
        await self.setup()
        return await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.DISABLE.value,
                self.alias,
                group_name,
            ]
        )

    # ============ Private Helper Methods ============

    def _parse_access_key_output(self, stdout: str) -> AccessKeyPair:
        """Parse access key and secret key from MC output."""
        access_key = None
        secret_key = None

        for line in stdout.split("\n"):
            line = line.strip()
            if "Access Key:" in line:
                access_key = line.split(":", 1)[1].strip()
            elif "Secret Key:" in line:
                secret_key = line.split(":", 1)[1].strip()

        return AccessKeyPair(access_key=access_key, secret_key=secret_key)

    def _parse_access_keys_list(self, stdout: str) -> List[str]:
        """Parse access keys list from MC output."""
        keys = []
        in_access_keys_section = False

        for line in stdout.split("\n"):
            line = line.strip()
            if "Access Keys:" in line:
                in_access_keys_section = True
                continue

            if in_access_keys_section and line and "," in line:
                # Extract access key (first part before comma)
                access_key = line.split(",")[0].strip()
                if access_key:
                    keys.append(access_key)

        return keys

    def _parse_group_members(self, group_info_output: str) -> List[str]:
        """Parse group members from 'mc admin group info' output."""
        for line in group_info_output.split("\n"):
            line = line.strip()
            if line.startswith("Members:"):
                members_str = line.replace("Members:", "").strip()
                if members_str and members_str != "[]":
                    # Parse members list - format could be [user1,user2] or user1,user2
                    members_str = members_str.strip("[]")
                    return [m.strip() for m in members_str.split(",") if m.strip()]
                break
        return []

    def _create_empty_group_error(self, group_name: str) -> CommandResult:
        """Create error result for empty group creation attempt."""
        return CommandResult(
            success=False,
            stdout="",
            stderr="Cannot create empty group - MinIO requires at least one member",
            return_code=1,
            command=f"admin group add {self.alias} {group_name} <members>",
        )

    def _create_user_not_in_group_error(
        self, username: str, group_name: str
    ) -> CommandResult:
        """Create error result for user not in group."""
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"User {username} is not a member of group {group_name}",
            return_code=1,
            command=f"admin group info {self.alias} {group_name}",
        )

    def _create_cannot_remove_last_member_error(self, group_name: str) -> CommandResult:
        """Create error result for removing last member."""
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"Cannot remove last member from group {group_name}. Delete the group instead.",
            return_code=1,
            command=f"admin group info {self.alias} {group_name}",
        )

    async def _recreate_group_with_members(
        self, group_name: str, members: List[str]
    ) -> CommandResult:
        """Delete and recreate group with specified members."""
        # Delete current group
        delete_result = await self._execute_command(
            [
                "admin",
                AdminCommand.GROUP.value,
                GroupAction.RM.value,
                self.alias,
                group_name,
            ]
        )

        if not delete_result.success:
            return delete_result

        # Recreate with remaining members
        return await self.create_group(group_name, members)

    async def _handle_non_empty_group_deletion(self, group_name: str) -> CommandResult:
        """Handle deletion of non-empty group."""
        logger.info(f"Group {group_name} is not empty, clearing all members first...")

        # Get current group info to see members
        group_info_result = await self.get_group_info(group_name)
        if not group_info_result.success:
            return group_info_result

        # Parse current members
        current_members = self._parse_group_members(group_info_result.stdout)
        logger.info(
            f"Found {len(current_members)} members in group {group_name}: {current_members}"
        )

        if current_members:
            # Delete the current group (force deletion)
            delete_result = await self._execute_command(
                [
                    "admin",
                    AdminCommand.GROUP.value,
                    GroupAction.RM.value,
                    self.alias,
                    group_name,
                ]
            )

            if delete_result.success:
                logger.info(f"Successfully deleted non-empty group {group_name}")
                return delete_result
            else:
                # If we still can't delete it, return the error
                return CommandResult(
                    success=False,
                    stdout="",
                    stderr=f"Cannot delete group {group_name}: {delete_result.stderr}",
                    return_code=delete_result.return_code or 1,
                    command=f"admin group rm {self.alias} {group_name}",
                )

        # If no members found, return original error
        return CommandResult(
            success=False,
            stdout="",
            stderr=f"Group {group_name} appears empty but cannot be deleted",
            return_code=1,
            command=f"admin group rm {self.alias} {group_name}",
        )

    # ============ Command Execution (DO NOT MODIFY) ============

    async def _execute_command(
        self, cmd_args: List[str], timeout: int = 30, input_data: Optional[str] = None
    ) -> CommandResult:
        """
        Execute MC command asynchronously with proper error handling and logging.

        Args:
            cmd_args: List of command arguments to pass to MC
            timeout: Command timeout in seconds
            input_data: Optional stdin data for the command

        Returns:
            CommandResult with execution details
        """
        cmd = [self._mc_path] + cmd_args
        command_str = " ".join(cmd)

        logger.debug(f"Executing MC command: {command_str}")

        try:
            # Create subprocess asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
            )

            # Execute with timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(
                        input=input_data.encode() if input_data else None
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass  # Process already terminated

                logger.error(f"MC command timed out after {timeout}s: {command_str}")
                return CommandResult(
                    success=False,
                    stdout="",
                    stderr=f"Command timed out after {timeout} seconds",
                    return_code=-1,
                    command=command_str,
                )

            # Decode output
            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
            return_code = process.returncode

            # Create result
            result = CommandResult(
                success=(return_code == 0),
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                command=command_str,
            )

            # Log results
            if result.success:
                logger.debug(f"MC command succeeded: {command_str}")
                if stdout:
                    logger.debug(f"Command output: {stdout[:200]}...")
            else:
                logger.error(f"MC command failed (code {return_code}): {command_str}")
                if stderr:
                    logger.error(f"Error output: {stderr}")

            return result

        except FileNotFoundError:
            error_msg = f"MC binary not found at path: {self._mc_path}"
            logger.error(error_msg)
            return CommandResult(
                success=False,
                stdout="",
                stderr=error_msg,
                return_code=-1,
                command=command_str,
            )

        except PermissionError:
            error_msg = f"Permission denied executing MC binary: {self._mc_path}"
            logger.error(error_msg)
            return CommandResult(
                success=False,
                stdout="",
                stderr=error_msg,
                return_code=-1,
                command=command_str,
            )

        except Exception as e:
            error_msg = f"Unexpected error executing MC command: {str(e)}"
            logger.error(f"{error_msg} - Command: {command_str}")
            return CommandResult(
                success=False,
                stdout="",
                stderr=error_msg,
                return_code=-1,
                command=command_str,
            )
