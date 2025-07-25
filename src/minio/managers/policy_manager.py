import json
import logging
import tempfile
from pathlib import Path
from typing import List, Optional

from ...service.exceptions import PolicyOperationError
from ..core.minio_client import MinIOClient
from ..core.policy_builder import PolicyBuilder
from ..core.policy_creator import PolicyCreator
from ..models.command import PolicyAction as CommandPolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyTarget,
    PolicyType,
)
from ..utils.validators import (
    DATA_GOVERNANCE_POLICY_PREFIXES,
    GROUP_POLICY_PREFIX,
    USER_HOME_POLICY_PREFIX,
    USER_SYSTEM_POLICY_PREFIX,
    validate_policy_name,
)
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

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
        return validate_policy_name(name)

    def _build_exists_command(self, name: str) -> List[str]:
        """Build command to check if policy exists."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.INFO, name
        )

    def _build_list_command(self) -> List[str]:
        """Build command to list all policies."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.LIST, json_format=True
        )

    def _build_delete_command(self, name: str) -> List[str]:
        """Build command to delete a policy."""
        return self._command_builder.build_policy_command(
            CommandPolicyAction.DELETE, name
        )

    def _parse_list_output(self, stdout: str) -> List[str]:
        """Parse policy list command JSON output."""
        try:
            policy_names = []
            # Each line is a separate JSON object with format: {"status":"success","policy":"policyname",...}
            for line in stdout.strip().split("\n"):
                if line.strip():
                    policy_data = json.loads(line)
                    policy_names.append(policy_data["policy"])
            return policy_names
        except Exception as e:
            raise PolicyOperationError(
                f"Failed to parse policy list command output: {stdout}"
            ) from e

    # === CORE POLICY CRUD OPERATIONS ===

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

    # === USER/GROUP POLICY MANAGEMENT ===

    async def ensure_user_policies(
        self, username: str
    ) -> tuple[PolicyModel, PolicyModel]:
        """
        Ensure both home and system policies exist for a user.

        This method guarantees that the user has both required policies:
        - Home policy: Access to user's personal warehouses
        - System policy: Access to system resources (logs, etc.)

        If policies already exist, they are returned as-is. If they don't exist,
        they are created with default permissions. This method is safe to call
        multiple times and will not fail if policies already exist.

        Args:
            username: Username to ensure policies for
        """
        async with self.operation_context("create_user_policy"):
            # Create both policy models
            home_policy = self._create_user_home_policy(username)
            system_policy = self._create_user_system_policy(username)

            # Check if home policy already exists
            # NOTE: Race condition possible - policy could be created between this check and creation
            home_exists = await self.resource_exists(home_policy.policy_name)
            if home_exists:
                logger.info(
                    f"User home policy already exists: {home_policy.policy_name}"
                )
                # Load existing policy to return
                home_policy = await self._load_minio_policy(home_policy.policy_name)
            else:
                # Create home policy
                # NOTE: _create_minio_policy will overwrite existing policies
                await self._create_minio_policy(home_policy)
                logger.info(f"Created user home policy: {home_policy.policy_name}")

            # Check if system policy already exists
            # NOTE: Race condition possible - policy could be created between this check and creation
            system_exists = await self.resource_exists(system_policy.policy_name)
            if system_exists:
                logger.info(
                    f"User system policy already exists: {system_policy.policy_name}"
                )
                # Load existing policy to return
                system_policy = await self._load_minio_policy(system_policy.policy_name)
            else:
                # Create system policy
                # NOTE: _create_minio_policy will overwrite existing policies
                await self._create_minio_policy(system_policy)
                logger.info(f"Created system policy: {system_policy.policy_name}")

            return home_policy, system_policy  # type: ignore

    def _create_policy_model(
        self, policy_type: PolicyType, target_name: str
    ) -> PolicyModel:
        """Create a policy model for the given type and target."""
        try:
            builder = PolicyCreator(
                policy_type=policy_type,
                target_name=target_name,
                config=self.config,
            )
            return builder.create_default_policy().build()
        except Exception as e:
            policy_desc = policy_type.value.replace("_", " ")
            logger.error(
                f"Failed to create {policy_desc} policy for {target_name}: {e}"
            )
            raise PolicyOperationError(
                f"Failed to create {policy_desc} policy: {e}"
            ) from e

    def _create_user_home_policy(self, username: str) -> PolicyModel:
        """Create user home policy"""
        return self._create_policy_model(PolicyType.USER_HOME, username)

    def _create_user_system_policy(self, username: str) -> PolicyModel:
        """Create user system policy"""
        return self._create_policy_model(PolicyType.USER_SYSTEM, username)

    async def ensure_group_policy(self, group_name: str) -> PolicyModel:
        """
        Ensure group policy exists for a group.

        This method guarantees that the group has a policy for shared workspace access.
        The policy provides access to the group's shared directory structure.

        If the policy already exists, it is returned as-is. If it doesn't exist,
        it is created with default group permissions. This method is safe to call
        multiple times and will not fail if the policy already exists.

        Args:
            group_name: Group name to ensure policy for
        """
        async with self.operation_context("create_group_policy"):
            # Create group policy model (Currently only group home policy)
            group_policy = self._create_group_home_policy(group_name)

            # Check if policy already exists
            # NOTE: Race condition possible - policy could be created between this check and creation
            policy_exists = await self.resource_exists(group_policy.policy_name)
            if policy_exists:
                logger.info(f"Group policy already exists: {group_policy.policy_name}")
                # Load existing policy to return
                group_policy = await self._load_minio_policy(group_policy.policy_name)
            else:
                # Create the policy in MinIO
                # NOTE: _create_minio_policy will overwrite existing policies
                await self._create_minio_policy(group_policy)
                logger.info(f"Created group policy: {group_policy.policy_name}")

            return group_policy  # type: ignore

    def _create_group_home_policy(self, group_name: str) -> PolicyModel:
        """Create group home policy"""
        return self._create_policy_model(PolicyType.GROUP_HOME, group_name)

    async def get_user_home_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's home policy from MinIO.

        Args:
            username: Username to get home policy for
        """
        async with self.operation_context("get_user_home_policy"):
            policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"User home policy {policy_name} not found or unsupported"
                )
            return result

    async def get_user_system_policy(self, username: str) -> PolicyModel:
        """
        Retrieve the user's system policy from MinIO.

        Args:
            username: Username to get system policy for
        """
        async with self.operation_context("get_user_system_policy"):
            policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"User system policy {policy_name} not found or unsupported"
                )
            return result

    async def get_group_policy(self, group_name: str) -> PolicyModel:
        """
        Retrieve the existing policy for a specific group with proper error handling.

        Args:
            group_name: Group name to get policy for
        """
        async with self.operation_context("get_group_policy"):
            policy_name = self.get_policy_name(PolicyType.GROUP_HOME, group_name)
            result = await self._load_minio_policy(policy_name)
            if result is None:
                raise PolicyOperationError(
                    f"Group policy {policy_name} not found or unsupported"
                )
            return result

    async def delete_user_policies(self, username: str) -> None:
        """
        Delete both home and system policies for a user.

        Args:
            username: Username to delete policies for

        Raises:
            PolicyOperationError: If policy deletion fails
        """
        async with self.operation_context("delete_user_policy"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            errors = []

            # Try to delete home policy
            try:
                success = await self.delete_resource(home_policy_name)
                if success:
                    logger.info(f"Deleted user home policy: {home_policy_name}")
                else:
                    errors.append(f"Failed to delete home policy: {home_policy_name}")
            except Exception as e:
                logger.error(f"Error deleting home policy {home_policy_name}: {e}")
                errors.append(f"Error deleting home policy: {e}")

            # Try to delete system policy
            try:
                success = await self.delete_resource(system_policy_name)
                if success:
                    logger.info(f"Deleted system policy: {system_policy_name}")
                else:
                    errors.append(
                        f"Failed to delete system policy: {system_policy_name}"
                    )
            except Exception as e:
                logger.error(f"Error deleting system policy {system_policy_name}: {e}")
                errors.append(f"Error deleting system policy: {e}")

            # Raise error if any deletions failed
            if errors:
                error_msg = "; ".join(errors)
                raise PolicyOperationError(
                    f"Failed to delete user policies: {error_msg}"
                )

    async def delete_group_policy(self, group_name: str) -> None:
        """
        Delete a group's policy from MinIO with proper cleanup.

        Args:
            group_name: Group name to delete policy for
        """
        async with self.operation_context("delete_group_policy"):
            policy_name = self.get_policy_name(PolicyType.GROUP_HOME, group_name)

            success = await self.delete_resource(policy_name)
            if not success:
                raise PolicyOperationError(
                    f"Failed to delete group policy: {policy_name}"
                )
            logger.info(f"Deleted group policy: {policy_name}")

    # === POLICY ATTACHMENT OPERATIONS ===

    async def attach_user_policies(self, username: str) -> None:
        """
        Attach both home and system policies to a user.

        Args:
            username: Username to attach policies to

        Raises:
            PolicyOperationError: If policy attachment fails or policies don't exist
        """
        async with self.operation_context("attach_user_policies"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            # Check if policies are already attached
            home_already_attached = await self._is_policy_attached_to_target(
                home_policy_name, PolicyTarget.USER, username
            )
            system_already_attached = await self._is_policy_attached_to_target(
                system_policy_name, PolicyTarget.USER, username
            )

            # Skip if both policies are already attached
            if home_already_attached and system_already_attached:
                logger.info(f"Both policies already attached to user {username}")
                return

            # Validate that both policies exist before attachment
            try:
                home_policy = await self._load_minio_policy(home_policy_name)
                system_policy = await self._load_minio_policy(system_policy_name)
                if home_policy is None or system_policy is None:
                    raise PolicyOperationError(
                        "One or both policies do not exist or are unsupported"
                    )
            except Exception as e:
                raise PolicyOperationError(
                    f"Cannot attach policies - one or both policies do not exist: {e}"
                ) from e

            # Track attachment state for rollback
            home_attached = home_already_attached
            system_attached = system_already_attached

            try:
                # Attach home policy if not already attached
                if not home_already_attached:
                    await self.attach_policy_to_user(home_policy_name, username)
                    home_attached = True
                    logger.info(
                        f"Attached home policy {home_policy_name} to user {username}"
                    )

                # Attach system policy if not already attached
                if not system_already_attached:
                    await self.attach_policy_to_user(system_policy_name, username)
                    system_attached = True
                    logger.info(
                        f"Attached system policy {system_policy_name} to user {username}"
                    )

            except Exception as e:
                # Implement rollback logic for partial attachment failures
                logger.error(f"Policy attachment failed, attempting rollback: {e}")

                rollback_errors = []

                # Rollback system policy if it was attached
                if system_attached:
                    try:
                        await self.detach_policy_from_user(system_policy_name, username)
                        logger.info(
                            f"Rolled back system policy attachment for {username}"
                        )
                    except Exception as rollback_error:
                        rollback_errors.append(
                            f"Failed to rollback system policy: {rollback_error}"
                        )

                # Rollback home policy if it was attached
                if home_attached:
                    try:
                        await self.detach_policy_from_user(home_policy_name, username)
                        logger.info(
                            f"Rolled back home policy attachment for {username}"
                        )
                    except Exception as rollback_error:
                        rollback_errors.append(
                            f"Failed to rollback home policy: {rollback_error}"
                        )

                # Construct error message
                error_msg = f"Failed to attach user policies: {e}"
                if rollback_errors:
                    error_msg += f"; Rollback errors: {'; '.join(rollback_errors)}"

                raise PolicyOperationError(error_msg) from e

    async def detach_user_policies(self, username: str) -> None:
        """
        Detach both home and system policies from a user.

        Args:
            username: Username to detach policies from

        Raises:
            PolicyOperationError: If policy detachment fails
        """
        async with self.operation_context("detach_user_policies"):
            home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
            system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

            errors = []

            # Try to detach home policy
            try:
                await self.detach_policy_from_user(home_policy_name, username)
                logger.info(
                    f"Detached home policy {home_policy_name} from user {username}"
                )
            except Exception as e:
                logger.error(f"Error detaching home policy {home_policy_name}: {e}")
                errors.append(f"Error detaching home policy: {e}")

            # Try to detach system policy
            try:
                await self.detach_policy_from_user(system_policy_name, username)
                logger.info(
                    f"Detached system policy {system_policy_name} from user {username}"
                )
            except Exception as e:
                logger.error(f"Error detaching system policy {system_policy_name}: {e}")
                errors.append(f"Error detaching system policy: {e}")

            # Raise error if any detachments failed
            if errors:
                error_msg = "; ".join(errors)
                raise PolicyOperationError(
                    f"Failed to detach user policies: {error_msg}"
                )

    async def attach_policy_to_user(self, policy_name: str, username: str) -> None:
        """
        Attach an existing policy to a user, granting them the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            username: The username to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.USER, username, attach=True
        )

    async def detach_policy_from_user(self, policy_name: str, username: str) -> None:
        """
        Detach a policy from a user, removing the policy's permissions from the user.

        Args:
            policy_name: The name of the policy to detach
            username: The username to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.USER, username, attach=False
        )

    async def attach_policy_to_group(self, policy_name: str, group_name: str) -> None:
        """
        Attach an existing policy to a group, granting all group members the policy's permissions.

        Args:
            policy_name: The name of the policy to attach
            group_name: The group name to attach the policy to
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.GROUP, group_name, attach=True
        )

    async def detach_policy_from_group(self, policy_name: str, group_name: str) -> None:
        """
        Detach a policy from a group, removing the policy's permissions from all group members.

        Args:
            policy_name: The name of the policy to detach
            group_name: The group name to detach the policy from
        """
        await self._attach_detach_policy(
            policy_name, PolicyTarget.GROUP, group_name, attach=False
        )

    async def is_policy_attached_to_group(self, group_name: str) -> bool:
        """
        Check if the group's policy is attached to the group.

        Args:
            group_name: The name of the group to check

        Returns:
            bool: True if the group's policy is attached to the group, False otherwise
        """
        policy_name = self.get_policy_name(PolicyType.GROUP_HOME, group_name)
        return await self._is_policy_attached_to_target(
            policy_name, PolicyTarget.GROUP, group_name
        )

    async def is_policies_attached_to_user(self, username: str) -> bool:
        """
        Check if both user policies (home and system) are attached to the user.

        Args:
            username: The name of the user to check

        Returns:
            bool: True if BOTH user policies are attached to the user, False otherwise
        """
        home_policy_name = self.get_policy_name(PolicyType.USER_HOME, username)
        system_policy_name = self.get_policy_name(PolicyType.USER_SYSTEM, username)

        home_attached = await self._is_policy_attached_to_target(
            home_policy_name, PolicyTarget.USER, username
        )
        system_attached = await self._is_policy_attached_to_target(
            system_policy_name, PolicyTarget.USER, username
        )

        return home_attached and system_attached

    async def _attach_detach_policy(
        self,
        policy_name: str,
        target_type: PolicyTarget,
        target_name: str,
        attach: bool,
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

    async def _is_policy_attached_to_target(
        self, policy_name: str, target_type: PolicyTarget, target_name: str
    ) -> bool:
        """Check if a specific policy is attached to a target (user or group)."""
        entities = await self._get_policy_attached_entities(policy_name)
        return target_name in entities[target_type]

    async def _get_policy_attached_entities(
        self, policy_name: str
    ) -> dict[PolicyTarget, list[str]]:
        """Get all entities (users and groups) that have a specific policy attached."""
        cmd_args = self._command_builder.build_policy_entities_command(policy_name)
        result = await self._executor._execute_command(cmd_args)

        if not result.success:
            raise PolicyOperationError(
                f"Failed to get entities for policy {policy_name}: {result.stderr}"
            )

        return self._parse_policy_entities_output(result.stdout)

    def _parse_policy_entities_output(
        self, output: str
    ) -> dict[PolicyTarget, list[str]]:
        """Parse the JSON output of 'mc admin policy entities --json' command."""

        entities = {PolicyTarget.USER: [], PolicyTarget.GROUP: []}

        # Parse the JSON output
        data = json.loads(output.strip())

        # Extract policy mappings from result
        result = data.get("result", {})
        policy_mappings = result.get("policyMappings", [])

        # Process each policy mapping
        for mapping in policy_mappings:
            # Extract users
            users = mapping.get("users", [])
            if users:
                entities[PolicyTarget.USER].extend(users)

            # Extract groups
            groups = mapping.get("groups", [])
            if groups:
                entities[PolicyTarget.GROUP].extend(groups)

        return entities

    # === POLICY DOCUMENT MANIPULATION ===

    def add_path_access_to_policy(
        self,
        policy_model: PolicyModel,
        path: str,
        permission_level: PolicyPermissionLevel,
    ) -> PolicyModel:
        """
        Add access permissions for a specific path to an existing policy model.

        This method uses the PolicyBuilder pattern to create a new policy model
        with the added path access. The original policy model is not modified.

        Args:
            policy_model: The policy model to base modifications on
            path: The S3 path to grant access to (e.g., "s3a://bucket/path/to/data")
            permission_level: The level of access to grant (READ, WRITE, or ADMIN)

        Note:
            This method only modifies the policy model in memory. Call update_policy()
            to persist the changes to MinIO.
        """
        try:
            builder = PolicyBuilder(policy_model, self.config.default_bucket)
            return builder.add_path_access(path, permission_level).build()
        except Exception as e:
            logger.error(
                f"Failed to add path access {path} to policy {policy_model.policy_name}: {e}"
            )
            raise PolicyOperationError(f"Failed to add path access: {e}") from e

    def remove_path_access_from_policy(
        self, policy_model: PolicyModel, path: str
    ) -> PolicyModel:
        """
        Remove access permissions for a specific path from an existing policy model.

        This method uses the PolicyBuilder pattern to create a new policy model
        with the path access removed. The original policy model is not modified.

        Args:
            policy_model: The policy model to base modifications on
            path: The S3 path to revoke access from (e.g., "s3a://bucket/path/to/data")

        Note:
            This method only modifies the policy model in memory. Call update_policy()
            to persist the changes to MinIO.
        """
        try:
            builder = PolicyBuilder(policy_model, self.config.default_bucket)
            return builder.remove_path_access(path).build()
        except Exception as e:
            logger.error(
                f"Failed to remove path access {path} from policy {policy_model.policy_name}: {e}"
            )
            raise PolicyOperationError(f"Failed to remove path access: {e}") from e

    # === POLICY ANALYSIS METHODS ===

    def get_accessible_paths_from_policy(self, policy_model: PolicyModel) -> list[str]:
        """
        Extract all S3 paths that are accessible through the given policy.

        This method analyzes all statements in the policy and extracts the S3 paths
        that the policy grants access to. It converts internal ARN formats back to
        user-friendly s3a:// URLs.

        Args:
            policy_model: The policy model to analyze
        """
        paths: set[str] = set()

        for statement in policy_model.policy_document.statement:
            if statement.effect == PolicyEffect.ALLOW:
                extracted_paths = self._extract_paths_from_statement(statement)
                paths.update(extracted_paths)

        return sorted(paths)

    def _extract_paths_from_statement(self, statement: PolicyStatement) -> set[str]:
        """Extract accessible paths from a policy statement."""
        paths: set[str] = set()
        resources = self._normalize_resources_to_list(statement.resource)

        for resource in resources:
            if path := self._extract_path_from_resource_arn(resource):
                paths.add(path)

        return paths

    def _normalize_resources_to_list(self, resource: str | list[str]) -> list[str]:
        """Normalize resource field to a list of strings."""
        return resource if isinstance(resource, list) else [resource]

    def _extract_path_from_resource_arn(self, resource: str) -> str | None:
        """Extract s3a:// path from ARN resource string."""
        if (
            not isinstance(resource, str)
            or "arn:aws:s3:::" not in resource
            or "/*" not in resource
        ):
            return None

        arn_content = resource.split("arn:aws:s3:::")[1]
        if not arn_content.endswith("/*"):
            return None

        path_without_wildcard = arn_content.removesuffix("/*")
        path_parts = path_without_wildcard.split("/")

        if len(path_parts) < 2:
            return None

        bucket, *path_segments = path_parts
        path = "/".join(path_segments)
        return f"s3a://{bucket}/{path}/"

    # === LISTING AND UTILITY METHODS ===

    def get_policy_name(self, policy_type: PolicyType, target_name: str) -> str:
        """
        Generate a standardized policy name for a user or group.

        Args:
            policy_type: The policy type (USER_HOME/USER_SYSTEM/GROUP_HOME)
            target_name: The username or group name
        """

        try:
            builder = PolicyCreator(
                policy_type=policy_type,
                target_name=target_name,
                config=self.config,
            )
            return builder._generate_policy_name()
        except Exception as e:
            raise PolicyOperationError(f"Failed to generate policy name: {e}") from e

    async def list_all_policies(self) -> List[PolicyModel]:
        """
        Retrieve all policies from MinIO as complete PolicyModel objects.

        This method fetches all policies from the MinIO server and loads their
        complete policy documents including statements, permissions, and conditions.
        This is useful for administrative operations and policy auditing.

        Returns:
            List[PolicyModel]: A list of all policies with complete policy documents

        Raises:
            PolicyOperationError: If listing policies fails

        Note:
            This operation can be expensive if there are many policies, as it loads
            the complete policy document for each policy.
        """
        try:
            # Get policy names using generic implementation
            policy_names = await self.list_resources()

            # Load full PolicyModel objects for each policy
            policies = []
            for policy_name in policy_names:
                policy_model = await self._load_minio_policy(policy_name)
                if policy_model:
                    policies.append(policy_model)

            return policies
        except Exception:
            raise PolicyOperationError("Failed to list all policies")

    # === MinIO POLICY OPERATIONS ===

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
            # NOTE: If policy already exists, it will be overwritten.
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

        # Determine policy type and target
        target_name = None
        policy_type = None

        if self.is_user_home_policy(policy_name):
            target_name = policy_name.replace(USER_HOME_POLICY_PREFIX, "")
            policy_type = PolicyType.USER_HOME
        elif self.is_user_system_policy(policy_name):
            target_name = policy_name.replace(USER_SYSTEM_POLICY_PREFIX, "")
            policy_type = PolicyType.USER_SYSTEM
        elif self.is_group_policy(policy_name):
            target_name = policy_name.replace(GROUP_POLICY_PREFIX, "")
            policy_type = PolicyType.GROUP_HOME
        else:
            raise PolicyOperationError(
                f"Unknown policy naming pattern: {policy_name}. "
                f"Expected {USER_HOME_POLICY_PREFIX}, {USER_SYSTEM_POLICY_PREFIX}, or {GROUP_POLICY_PREFIX} prefix."
            )

        logger.info(f"Updating {policy_type} policy {policy_name} for {target_name}")

        # For user policies (home or system), detach the specific policy first
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            logger.info(
                f"Detected user policy {policy_name} for user {target_name}, detaching specific policy first"
            )
            await self.detach_policy_from_user(policy_name, target_name)
            logger.info(f"Successfully detached {policy_name} from user {target_name}")

        # For group policies, detach the specific group policy
        elif policy_type == PolicyType.GROUP_HOME:
            logger.info(
                f"Detected group policy {policy_name} for group {target_name}, detaching first"
            )
            await self.detach_policy_from_group(policy_name, target_name)
            logger.info(f"Successfully detached {policy_name} from group {target_name}")

        # Now delete and recreate the policy
        logger.info(f"Deleting policy {policy_name}")
        await self.delete_resource(policy_name)
        logger.info(f"Creating updated policy {policy_name}")
        # NOTE: _create_minio_policy will overwrite existing policies
        await self._create_minio_policy(policy_model)

        # Reattach the updated policy appropriately
        if policy_type in [PolicyType.USER_HOME, PolicyType.USER_SYSTEM]:
            # For user policies, reattach the specific updated policy
            logger.info(
                f"Reattaching updated policy {policy_name} to user {target_name}"
            )
            await self.attach_policy_to_user(policy_name, target_name)
            logger.info(f"Successfully reattached {policy_name} to user {target_name}")

        elif policy_type == PolicyType.GROUP_HOME:
            # For group policies, reattach the specific group policy
            await self.attach_policy_to_group(policy_name, target_name)
            logger.info(f"Reattached {policy_name} to group {target_name}")

    async def _load_minio_policy(self, policy_name: str) -> Optional[PolicyModel]:
        """Load a policy from MinIO using the command executor. Returns None for unsupported built-in policies."""
        # Skip MinIO policies (built-in policies) that are not data governance policies
        if not any(
            policy_name.startswith(prefix) for prefix in DATA_GOVERNANCE_POLICY_PREFIXES
        ):
            logger.debug(f"Skipping MinIO policy: {policy_name}")
            return None

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
        try:
            policy_document = PolicyDocument.from_dict(policy_json)
        except Exception as e:
            raise PolicyOperationError(
                f"Failed to load policy {policy_name}: {e}"
            ) from e

        return PolicyModel(
            policy_name=policy_name,
            policy_document=policy_document,
        )

    def is_user_system_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a system policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a system policy, False otherwise
        """
        return policy_name.startswith(USER_SYSTEM_POLICY_PREFIX)

    def is_user_home_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a user home policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a user home policy, False otherwise
        """
        return policy_name.startswith(USER_HOME_POLICY_PREFIX)

    def is_group_policy(self, policy_name: str) -> bool:
        """
        Check if a policy is a group policy.

        Args:
            policy_name: Policy name to check

        Returns:
            True if policy is a group policy, False otherwise
        """
        return policy_name.startswith(GROUP_POLICY_PREFIX)
