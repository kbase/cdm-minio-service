"""
Policy Builder module for modifying MinIO policy documents.
"""

import logging
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from ...service.exceptions import PolicyOperationError
from ..models.policy import (
    PERMISSION_LEVEL_ACTIONS,
    PolicyAction,
    PolicyEffect,
    PolicyModel,
    PolicyPermissionLevel,
    PolicyStatement,
)

logger = logging.getLogger(__name__)


class PathAccess(BaseModel):
    """Represents access to a specific S3 path with permission level."""

    model_config = ConfigDict(frozen=True)

    path: Annotated[str, Field(description="S3 path for access control", min_length=1)]
    permission_level: Annotated[
        PolicyPermissionLevel, Field(description="Level of access permission")
    ]


class PolicyBuilder:

    def __init__(self, policy_model: PolicyModel, bucket_name: str):
        """
        Initialize the PolicyBuilder with a policy model and bucket name.

        Args:
            policy_model: The base policy model to modify
            bucket_name: The S3 bucket name for path validation
        """
        self.policy_model = policy_model.model_copy(deep=True)
        self.bucket_name = bucket_name

    def add_path_access(
        self, path: str, permission_level: PolicyPermissionLevel
    ) -> "PolicyBuilder":
        """
        Add access to a path with specified permission level.

        Args:
            path: The S3 path to grant access to (e.g., "s3a://bucket/path/to/data")
            permission_level: The level of access to grant (READ, WRITE, or ADMIN)

        Returns:
            PolicyBuilder: A new builder instance with the path access added

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        clean_path = self._normalize_path(path)
        path_access = PathAccess(path=clean_path, permission_level=permission_level)

        # Create new builder with modifications
        new_builder = PolicyBuilder(self.policy_model, self.bucket_name)
        new_builder._add_path_access_internal(path_access)
        return new_builder

    def remove_path_access(self, path: str) -> "PolicyBuilder":
        """
        Remove all access to a specific path.

        Args:
            path: The S3 path to revoke access from (e.g., "s3a://bucket/path/to/data")

        Returns:
            PolicyBuilder: A new builder instance with the path access removed

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        clean_path = self._normalize_path(path)

        # Create new builder with modifications
        new_builder = PolicyBuilder(self.policy_model, self.bucket_name)
        new_builder._remove_path_access_internal(clean_path)
        return new_builder

    def build(self) -> PolicyModel:
        """
        Build the final policy model.

        Returns:
            PolicyModel: A deep copy of the modified policy model
        """
        return self.policy_model.model_copy(deep=True)

    def _add_path_access_internal(self, path_access: PathAccess) -> None:
        """Internal method to add path access to the policy."""
        # Remove any existing access to allow permission level changes
        self._remove_path_access_internal(path_access.path)

        # Add to ListBucket statement
        self._add_to_list_bucket_statement(path_access.path)

        # Add object-level statement
        self._add_object_statement(path_access.path, path_access.permission_level)

    def _remove_path_access_internal(self, clean_path: str) -> None:
        """Internal method to remove path access from the policy."""
        # Remove from ListBucket statement
        self._remove_from_list_bucket_statement(clean_path)

        # Remove object-level statements
        self._remove_object_statements(clean_path)

    def _normalize_path(self, path: str) -> str:
        """
        Normalize S3 path to bucket-relative format.

        Args:
            path: The S3 path to normalize

        Returns:
            str: The normalized path (bucket-relative)

        Raises:
            PolicyOperationError: If the path format is invalid
        """
        if not path.startswith(("s3://", "s3a://")):
            raise PolicyOperationError(
                f"Invalid S3 path format: {path}. Must start with s3:// or s3a://"
            )

        # Extract bucket and path from S3 URL
        path_without_scheme = re.sub(r"^s3a?://", "", path)
        path_parts = path_without_scheme.split("/", 1)

        if len(path_parts) < 2:
            raise PolicyOperationError(
                f"S3 path must include a path component after bucket: {path}"
            )

        bucket_in_path, relative_path = path_parts

        # Validate bucket matches configuration
        if bucket_in_path != self.bucket_name:
            raise PolicyOperationError(
                f"Path bucket '{bucket_in_path}' does not match configured bucket '{self.bucket_name}'"
            )

        return relative_path.rstrip("/")

    def _find_list_bucket_statement(self) -> PolicyStatement | None:
        """Find the ListBucket statement with prefix conditions."""
        for stmt in self.policy_model.policy_document.statement:
            if (
                PolicyAction.LIST_BUCKET
                in (stmt.action if isinstance(stmt.action, list) else [stmt.action])
                and stmt.condition
                and "StringLike" in stmt.condition
                and "s3:prefix" in stmt.condition["StringLike"]
            ):
                return stmt
        return None

    def _add_to_list_bucket_statement(self, clean_path: str) -> None:
        """Add path prefixes to the ListBucket statement in place."""
        list_bucket_stmt = self._find_list_bucket_statement()
        if not list_bucket_stmt or not list_bucket_stmt.condition:
            raise PolicyOperationError("No ListBucket statement found to add path to")

        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        new_prefixes = [f"{clean_path}/*", clean_path]

        for prefix in new_prefixes:
            if prefix not in prefixes:
                prefixes.append(prefix)

    def _remove_from_list_bucket_statement(self, clean_path: str) -> None:
        """Remove path prefixes from the ListBucket statement."""
        list_bucket_stmt = self._find_list_bucket_statement()
        if not list_bucket_stmt or not list_bucket_stmt.condition:
            raise PolicyOperationError("No ListBucket statement found to add path to")

        prefixes = list_bucket_stmt.condition["StringLike"]["s3:prefix"]
        prefixes_to_remove = {f"{clean_path}/*", clean_path}

        list_bucket_stmt.condition["StringLike"]["s3:prefix"] = [
            prefix for prefix in prefixes if prefix not in prefixes_to_remove
        ]

    def _add_object_statement(
        self, clean_path: str, permission_level: PolicyPermissionLevel
    ) -> None:
        """Add object-level permissions statement."""
        actions = PERMISSION_LEVEL_ACTIONS[permission_level]
        resource = f"arn:aws:s3:::{self.bucket_name}/{clean_path}/*"

        new_statement = PolicyStatement(
            effect=PolicyEffect.ALLOW,
            action=actions,
            resource=[resource],
            condition=None,
            principal=None,
        )

        self.policy_model.policy_document.statement.append(new_statement)

    def _remove_object_statements(self, clean_path: str) -> None:
        """Remove object-level statements that match the path."""
        target_resource = f"arn:aws:s3:::{self.bucket_name}/{clean_path}/*"

        statements_to_keep = []

        for stmt in self.policy_model.policy_document.statement:
            if not self._statement_matches_resource(stmt, target_resource):
                # Statement doesn't contain target resource, keep as-is
                statements_to_keep.append(stmt)
            else:
                # Statement contains target resource
                resources = (
                    stmt.resource
                    if isinstance(stmt.resource, list)
                    else [stmt.resource]
                )

                # Remove only the target resource
                remaining_resources = [r for r in resources if r != target_resource]

                # Only keep statement if it has remaining resources
                if remaining_resources:
                    # Create new statement with remaining resources
                    updated_stmt = stmt.model_copy(
                        update={"resource": remaining_resources}
                    )
                    statements_to_keep.append(updated_stmt)

        self.policy_model.policy_document.statement = statements_to_keep

    def _statement_matches_resource(
        self, statement: PolicyStatement, target_resource: str
    ) -> bool:
        """Check if a statement matches a specific resource."""

        resources = (
            statement.resource
            if isinstance(statement.resource, list)
            else [statement.resource]
        )
        return target_resource in resources
