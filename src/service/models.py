"""
Pydantic models for the MinIO Manager API.
"""

from typing import Annotated, Optional, List

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standard error response model."""

    error: Annotated[int | None, Field(description="Error code")] = None
    error_type: Annotated[str | None, Field(description="Error type")] = None
    message: Annotated[str | None, Field(description="Error message")] = None


class HealthResponse(BaseModel):
    """Health check response model."""

    status: Annotated[str, Field(description="Health status")]


class UserRequest(BaseModel):
    """Request model for creating a new user."""
    
    groups: Annotated[Optional[List[str]], Field(description="List of groups the user belongs to", default=None)]


class UserResponse(BaseModel):
    """Response model for user operations."""
    
    username: Annotated[str, Field(description="Username")]
    access_key: Annotated[str, Field(description="MinIO access key")]
    secret_key: Annotated[str, Field(description="MinIO secret key")]
    policy_name: Annotated[str, Field(description="MinIO policy name")]
    groups: Annotated[List[str], Field(description="List of groups the user belongs to")]
    home_path: Annotated[str, Field(description="User's home path in MinIO")]
    status: Annotated[str, Field(description="User status")]


class UserCredentials(BaseModel):
    """Response model for user credentials."""
    
    username: Annotated[str, Field(description="Username")]
    access_key: Annotated[str, Field(description="MinIO access key")]
    secret_key: Annotated[str, Field(description="MinIO secret key")]
    minio_endpoint: Annotated[str, Field(description="MinIO endpoint URL")]
    home_path: Annotated[str, Field(description="User's home path in MinIO")]


class ShareRequest(BaseModel):
    """Request model for sharing access to a path."""
    
    path: Annotated[str, Field(description="Path to share (e.g., 'warehouse/username/data')")]
    with_group: Annotated[str, Field(description="Group to share the path with")]
    permissions: Annotated[str, Field(description="Permission level: 'read' or 'write'", default="read")]


class UnshareRequest(BaseModel):
    """Request model for removing shared access to a path."""
    
    path: Annotated[str, Field(description="Path to unshare")]
    from_group: Annotated[str, Field(description="Group to remove access from")]


class GroupRequest(BaseModel):
    """Request model for creating or updating a group."""
    
    description: Annotated[Optional[str], Field(description="Group description", default=None)]
    members: Annotated[Optional[List[str]], Field(description="List of group members", default=None)]


class GroupResponse(BaseModel):
    """Response model for group operations."""
    
    group_name: Annotated[str, Field(description="Group name")]
    description: Annotated[Optional[str], Field(description="Group description")]
    members: Annotated[List[str], Field(description="List of group members")]
    policy_name: Annotated[str, Field(description="MinIO policy name for the group")]
    shared_paths: Annotated[List[dict], Field(description="List of shared paths and permissions")]


