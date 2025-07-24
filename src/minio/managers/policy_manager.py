import json
import logging
import tempfile
from enum import Enum
from pathlib import Path
from typing import List, Optional

from ...service.exceptions import PolicyOperationError
from ..core.minio_client import MinIOClient
from ..core.policy_builder import PolicyBuilder
from ..core.policy_creator import PolicyCreator
from ..models.command import PolicyAction as CommandPolicyAction
from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyAction,
    PolicyDocument,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
    PolicyType,
)
from ..utils.validators import DATA_GOVERNANCE_POLICY_PREFIXES, validate_policy_name
from .resource_manager import ResourceManager

logger = logging.getLogger(__name__)

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
            result = await self._load_minio_policy(policy_name)

            if result is None:
                raise PolicyOperationError(f"Policy {policy_name} not found")

            return result

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

    async def get_user_policy(self, username: str) -> PolicyModel:
        """Retrieve the existing policy for a specific user."""
        return await self.get_policy(TargetType.USER, username)

    async def get_group_policy(self, group_name: str) -> PolicyModel:
        """Retrieve the existing policy for a specific group."""
        return await self.get_policy(TargetType.GROUP, group_name)

    async def delete_user_policy(self, username: str) -> None:
        """Delete a user's policy from MinIO."""
        await self.delete_policy(TargetType.USER, username)

    async def delete_group_policy(self, group_name: str) -> None:
        """Delete a group's policy from MinIO."""
        await self.delete_policy(TargetType.GROUP, group_name)

    # === USER/GROUP POLICY MANAGEMENT ===

    async def create_user_policies(
        self, username: str
    ) -> tuple[PolicyModel, PolicyModel]:
        """
        Create both home and system policies for a user.

        Args:
            username: Username to create policies for

        Returns:
            Tuple of (home_policy, system_policy)
        """
        async with self.operation_context("create_user_policy"):
            # Create both policy models
            home_policy = self._create_user_home_policy(username)
            system_policy = self._create_user_system_policy(username)

            # Create both policies in MinIO
            await self._create_minio_policy(home_policy)
            logger.info(f"Created user home policy: {home_policy.policy_name}")
            await self._create_minio_policy(system_policy)
            logger.info(f"Created system policy: {system_policy.policy_name}")

            return home_policy, system_policy

    def _create_user_home_policy(self, username: str) -> PolicyModel:
        """Create user home policy"""
        try:
            builder = PolicyCreator(
                policy_type=PolicyType.USER_HOME,
                target_name=username,
                config=self.config,
            )
            return builder.create_default_policy().build()
        except Exception as e:
            logger.error(f"Failed to create user home policy for {username}: {e}")
            raise PolicyOperationError(f"Failed to create user home policy: {e}") from e

    def _create_user_system_policy(self, username: str) -> PolicyModel:
        """Create user system policy"""
        try:
            builder = PolicyCreator(
                policy_type=PolicyType.USER_SYSTEM,
                target_name=username,
                config=self.config,
            )
            return builder.create_default_policy().build()
        except Exception as e:
            logger.error(f"Failed to create system policy for {username}: {e}")
            raise PolicyOperationError(f"Failed to create system policy: {e}") from e

    async def create_group_policy(self, group_name: str) -> PolicyModel:
        """
        Create policy for a group.

        Args:
            group_name: Group name to create policy for
        """
        async with self.operation_context("create_group_policy"):
            # Create group policy (Currently only group home policy)
            group_policy = self._create_group_home_policy(group_name)

            # Create the policy in MinIO
            await self._create_minio_policy(group_policy)
            logger.info(f"Created group policy: {group_policy.policy_name}")
            return group_policy

    def _create_group_home_policy(self, group_name: str) -> PolicyModel:
        """Create group home policy"""
        try:
            builder = PolicyCreator(
                policy_type=PolicyType.GROUP_HOME,
                target_name=group_name,
                config=self.config,
            )
            return builder.create_default_policy().build()
        except Exception as e:
            logger.error(f"Failed to create group policy for {group_name}: {e}")
            raise PolicyOperationError(f"Failed to create group policy: {e}") from e

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

    async def is_policy_attached_to_group(self, group_name: str) -> bool:
        """
        Check if the group's policy is attached to the group.

        Args:
            group_name: The name of the group to check

        Returns:
            bool: True if the group's policy is attached to the group, False otherwise
        """
        policy_name = self.get_policy_name(TargetType.GROUP, group_name)
        return await self._is_policy_attached_to_target(
            policy_name, TargetType.GROUP, group_name
        )

    async def is_policy_attached_to_user(self, username: str) -> bool:
        """
        Check if the user's policy is attached to the user.

        Args:
            username: The name of the user to check

        Returns:
            bool: True if the user's policy is attached to the user, False otherwise
        """
        policy_name = self.get_policy_name(TargetType.USER, username)
        return await self._is_policy_attached_to_target(
            policy_name, TargetType.USER, username
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

    async def _is_policy_attached_to_target(
        self, policy_name: str, target_type: TargetType, target_name: str
    ) -> bool:
        """Check if a specific policy is attached to a target (user or group)."""
        entities = await self._get_policy_attached_entities(policy_name)
        return target_name in entities[target_type]

    async def _get_policy_attached_entities(
        self, policy_name: str
    ) -> dict[TargetType, list[str]]:
        """Get all entities (users and groups) that have a specific policy attached."""
        cmd_args = self._command_builder.build_policy_entities_command(policy_name)
        result = await self._executor._execute_command(cmd_args)

        if not result.success:
            raise PolicyOperationError(
                f"Failed to get entities for policy {policy_name}: {result.stderr}"
            )

        return self._parse_policy_entities_output(result.stdout)

    def _parse_policy_entities_output(self, output: str) -> dict[TargetType, list[str]]:
        """Parse the JSON output of 'mc admin policy entities --json' command."""

        entities = {TargetType.USER: [], TargetType.GROUP: []}

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
                entities[TargetType.USER].extend(users)

            # Extract groups
            groups = mapping.get("groups", [])
            if groups:
                entities[TargetType.GROUP].extend(groups)

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
            action=PolicyAction.LIST_ALL_MY_BUCKETS,
            resource=["*"],
            condition=None,
            principal=None,
        )

    def _create_bucket_location_statement(self) -> PolicyStatement:
        """Create statement for getting bucket location (required for MinIO users to see buckets in the UI)."""
        return PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=PolicyAction.GET_BUCKET_LOCATION,
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
            action=PolicyAction.LIST_BUCKET,
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
            # TODO: This will be refactored with future PRs - PolicyStatement allows only 1 action now
            action=PolicyAction.GET_OBJECT,
            resource=object_resources,
            condition=None,
            principal=None,
        )

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
