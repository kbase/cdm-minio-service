"""Policy-related Pydantic models for MinIO Manager Service"""

import json
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator
from typing_extensions import Annotated


class PolicyEffect(str, Enum):
    """Policy effect enumeration."""

    ALLOW = "Allow"
    DENY = "Deny"


class PolicyAction(str, Enum):
    """Common MinIO policy actions."""

    # Object actions
    GET_OBJECT = "s3:GetObject"
    PUT_OBJECT = "s3:PutObject"
    DELETE_OBJECT = "s3:DeleteObject"

    # Bucket actions
    LIST_BUCKET = "s3:ListBucket"

    # Administrative actions
    GET_BUCKET_LOCATION = "s3:GetBucketLocation"
    LIST_ALL_MY_BUCKETS = "s3:ListAllMyBuckets"

    # Wildcard
    ALL_ACTIONS = "s3:*"


class PolicyPermissionLevel(str, Enum):
    """Simplified permission levels."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class PolicyStatement(BaseModel):
    """Individual policy statement."""

    effect: Annotated[PolicyEffect, Field(description="Allow or Deny")]
    action: Annotated[
        Union[PolicyAction, List[PolicyAction], str, List[str]],
        Field(description="Actions to allow/deny"),
    ]
    resource: Annotated[Union[str, List[str]], Field(description="Resources affected")]
    condition: Annotated[
        Optional[Dict[str, Any]], Field(default=None, description="Conditional logic")
    ]
    principal: Annotated[
        Optional[Union[str, List[str]]],
        Field(default=None, description="Principal (for resource policies)"),
    ]

    def __eq__(self, other: object) -> bool:
        """Check if two policy statements are functionally equivalent."""
        if not isinstance(other, PolicyStatement):
            return False

        # Compare basic fields
        if self.effect != other.effect:
            return False
        if self.condition != other.condition:
            return False
        if self.principal != other.principal:
            return False

        # Compare actions (order doesn't matter)
        self_actions = (
            set(self.action) if isinstance(self.action, list) else {self.action}
        )
        other_actions = (
            set(other.action) if isinstance(other.action, list) else {other.action}
        )
        if self_actions != other_actions:
            return False

        # Compare resources (order doesn't matter)
        self_resources = (
            set(self.resource) if isinstance(self.resource, list) else {self.resource}
        )
        other_resources = (
            set(other.resource)
            if isinstance(other.resource, list)
            else {other.resource}
        )
        if self_resources != other_resources:
            return False

        return True

    def __hash__(self) -> int:
        """Make PolicyStatement hashable for use in sets/dicts."""
        # Convert lists to frozensets for hashability
        actions = (
            frozenset(self.action)
            if isinstance(self.action, list)
            else frozenset({self.action})
        )
        resources = (
            frozenset(self.resource)
            if isinstance(self.resource, list)
            else frozenset({self.resource})
        )

        # Convert condition dict to string for hashability (simplified approach)
        condition_str = str(sorted(self.condition.items())) if self.condition else None

        # Convert principal to frozenset (if exists)
        principal = (
            frozenset(self.principal)
            if isinstance(self.principal, list)
            else (frozenset({self.principal}) if self.principal else None)
        )

        return hash((self.effect, actions, resources, condition_str, principal))


class PolicyDocument(BaseModel):
    """Policy document structure."""

    version: Annotated[
        str, Field(default="2012-10-17", description="Policy language version")
    ] = "2012-10-17"
    statement: Annotated[List[PolicyStatement], Field(description="Policy statements")]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "Version": self.version,
            "Statement": [
                {
                    "Effect": stmt.effect.value,
                    "Action": stmt.action,
                    "Resource": stmt.resource,
                    **({"Condition": stmt.condition} if stmt.condition else {}),
                    **({"Principal": stmt.principal} if stmt.principal else {}),
                }
                for stmt in self.statement
            ],
        }

    @classmethod
    def from_dict(cls, policy_dict: Dict[str, Any]) -> "PolicyDocument":
        """Create from dictionary."""
        statements = []
        for stmt_dict in policy_dict.get("Statement", []):
            statements.append(
                PolicyStatement(
                    effect=PolicyEffect(stmt_dict["Effect"]),
                    action=stmt_dict["Action"],
                    resource=stmt_dict["Resource"],
                    condition=stmt_dict.get("Condition"),
                    principal=stmt_dict.get("Principal"),
                )
            )

        return cls(
            version=policy_dict.get("Version", "2012-10-17"), statement=statements
        )


class PolicyModel(BaseModel):
    """Complete policy model with metadata."""

    policy_name: Annotated[
        str, Field(min_length=1, max_length=128, description="Policy name")
    ]
    policy_document: Annotated[PolicyDocument, Field(description="Policy document")]

    @field_validator("policy_name")
    @classmethod
    def validate_policy_name(cls, v):
        """Validate policy name format."""
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(
                "Policy name can only contain letters, numbers, hyphens, underscores, and periods"
            )
        return v

    def to_minio_policy_json(self) -> str:
        """Convert to MinIO policy JSON string."""
        return json.dumps(self.policy_document.to_dict(), indent=2)
