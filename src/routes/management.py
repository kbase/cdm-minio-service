"""
Resource Management Routes for the MinIO Manager API.

This module provides administrative operations for managing
users, groups, and policies. These are admin-level operations
that require elevated privileges.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from ..minio.models.user import UserModel
from ..service.app_state import get_app_state
from ..service.dependencies import require_admin
from ..service.exceptions import GroupOperationError, UserOperationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/management", tags=["management"])


# ===== RESPONSE MODELS =====


class UserListResponse(BaseModel):
    """Response model for user listing."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    users: Annotated[list[UserModel], Field(description="List of users")]
    total_count: Annotated[int, Field(description="Total number of users", ge=0)]
    retrieved_count: Annotated[
        int, Field(description="Number of users retrieved", ge=0)
    ]


class UserManagementResponse(BaseModel):
    """Response model for user management operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    access_key: Annotated[str, Field(description="MinIO access key")]
    secret_key: Annotated[
        str, Field(description="MinIO secret key (only on creation/rotation)")
    ]
    home_paths: Annotated[list[str], Field(description="User home directory paths")]
    groups: Annotated[list[str], Field(description="Group memberships")]
    total_policies: Annotated[int, Field(description="Number of active policies", ge=0)]
    operation: Annotated[
        str, Field(description="Operation performed (create/update/rotate)")
    ]
    performed_by: Annotated[
        str, Field(description="Admin who performed the operation", min_length=1)
    ]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class GroupManagementResponse(BaseModel):
    """Response model for group management operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_name: Annotated[str, Field(description="Group name", min_length=1)]
    members: Annotated[list[str], Field(description="Group members")]
    member_count: Annotated[int, Field(description="Number of members", ge=0)]
    policy_name: Annotated[str, Field(description="Associated policy name")]
    operation: Annotated[
        str, Field(description="Operation performed (create/update/delete)")
    ]
    performed_by: Annotated[
        str, Field(description="Admin who performed the operation", min_length=1)
    ]
    timestamp: Annotated[datetime, Field(description="When operation was performed")]


class ResourceDeleteResponse(BaseModel):
    """Response model for resource deletion."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    resource_type: Annotated[str, Field(description="Type of resource deleted")]
    resource_name: Annotated[
        str, Field(description="Name of resource deleted", min_length=1)
    ]
    message: Annotated[str, Field(description="Human-readable message")]


# ===== USER MANAGEMENT ENDPOINTS =====


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all users",
    description="Get a list of all users in the system with basic information.",
)
async def list_users(
    request: Request,
    authenticated_user=Depends(require_admin),
    limit: Annotated[
        int,
        Query(ge=1, le=500, description="Maximum number of users to return"),
    ] = 50,
):
    """List all users in the system."""
    app_state = get_app_state(request)

    usernames = await app_state.user_manager.list_resources()
    limited_usernames = usernames[:limit]

    users = []
    for username in limited_usernames:
        try:
            user_info = await app_state.user_manager.get_user(username)
            users.append(user_info)
        except Exception as e:
            logger.warning(f"Failed to get info for user {username}: {e}")

    logger.info(f"Admin {authenticated_user.user} listed {len(users)} users")
    return UserListResponse(
        users=users,
        total_count=len(usernames),
        retrieved_count=len(users),
    )


@router.post(
    "/users/{username}",
    response_model=UserManagementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user with home directories and initial policy configuration.",
)
async def create_user(
    username: Annotated[str, Path(description="Username to create", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Create a new user account."""
    app_state = get_app_state(request)

    user_info = await app_state.user_manager.create_user(username=username)

    response = UserManagementResponse(
        username=user_info.username,
        access_key=user_info.access_key,
        secret_key=str(user_info.secret_key),
        home_paths=user_info.home_paths,
        groups=user_info.groups,
        total_policies=user_info.total_policies,
        operation="create",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(f"Admin {authenticated_user.user} created user {username}")
    return response


@router.post(
    "/users/{username}/rotate-credentials",
    response_model=UserManagementResponse,
    summary="Rotate user credentials",
    description="Force rotation of user credentials for security purposes.",
)
async def rotate_user_credentials(
    username: Annotated[str, Path(description="Username", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Rotate credentials for a user."""
    app_state = get_app_state(request)

    access_key, secret_key = (
        await app_state.user_manager.get_or_rotate_user_credentials(username)
    )
    user_info = await app_state.user_manager.get_user(username)

    response = UserManagementResponse(
        username=username,
        access_key=access_key,
        secret_key=secret_key,
        home_paths=user_info.home_paths,
        groups=user_info.groups,
        total_policies=user_info.total_policies,
        operation="rotate",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} rotated credentials for user {username}"
    )
    return response


@router.delete(
    "/users/{username}",
    response_model=ResourceDeleteResponse,
    summary="Delete user",
    description="Delete user account and cleanup all associated resources.",
)
async def delete_user(
    username: Annotated[str, Path(description="Username to delete", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Delete a user account."""
    app_state = get_app_state(request)

    success = await app_state.user_manager.delete_resource(username)
    if not success:
        raise UserOperationError(f"Failed to delete user {username}")

    response = ResourceDeleteResponse(
        resource_type="user",
        resource_name=username,
        message=f"User {username} deleted successfully",
    )

    logger.info(f"Admin {authenticated_user.user} deleted user {username}")
    return response


# ===== GROUP MANAGEMENT ENDPOINTS =====


@router.get(
    "/groups",
    summary="List all groups",
    description="Get a list of all groups in the system with membership information.",
)
async def list_groups(
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """List all groups in the system."""
    app_state = get_app_state(request)

    group_names = await app_state.group_manager.list_resources()

    groups = []
    for group_name in group_names:
        try:
            group_info = await app_state.group_manager.get_group_info(group_name)
            groups.append(
                {
                    "group_name": group_info.group_name,
                    "members": group_info.members,
                    "member_count": len(group_info.members),
                    "policy_name": group_info.policy_name,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to get info for group {group_name}: {e}")

    logger.info(f"Admin {authenticated_user.user} listed {len(groups)} groups")
    return {"groups": groups, "total_count": len(group_names)}


@router.post(
    "/groups/{group_name}",
    response_model=GroupManagementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create group",
    description="Create a new group with shared workspace and policy configuration.",
)
async def create_group(
    group_name: Annotated[str, Path(description="Group name to create", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Create a new group."""
    app_state = get_app_state(request)

    group_info = await app_state.group_manager.create_group(
        group_name=group_name,
        creator=authenticated_user.user,
    )

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
        operation="create",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(f"Admin {authenticated_user.user} created group {group_name}")
    return response


@router.post(
    "/groups/{group_name}/members/{username}",
    response_model=GroupManagementResponse,
    summary="Add group member",
    description="Add a user to the specified group.",
)
async def add_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    username: Annotated[str, Path(description="Username to add", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Add a member to a group."""
    app_state = get_app_state(request)

    await app_state.group_manager.add_user_to_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
        operation="add_member",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} added {username} to group {group_name}"
    )
    return response


@router.delete(
    "/groups/{group_name}/members/{username}",
    response_model=GroupManagementResponse,
    summary="Remove group member",
    description="Remove a user from the specified group.",
)
async def remove_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    username: Annotated[str, Path(description="Username to remove", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Remove a member from a group."""
    app_state = get_app_state(request)

    await app_state.group_manager.remove_user_from_group(username, group_name)

    # Get updated group info
    group_info = await app_state.group_manager.get_group_info(group_name)

    response = GroupManagementResponse(
        group_name=group_info.group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        policy_name=str(group_info.policy_name),
        operation="remove_member",
        performed_by=authenticated_user.user,
        timestamp=datetime.now(),
    )

    logger.info(
        f"Admin {authenticated_user.user} removed {username} from group {group_name}"
    )
    return response


@router.delete(
    "/groups/{group_name}",
    response_model=ResourceDeleteResponse,
    summary="Delete group",
    description="Delete group and cleanup all associated resources.",
)
async def delete_group(
    group_name: Annotated[str, Path(description="Group name to delete", min_length=1)],
    request: Request,
    authenticated_user=Depends(require_admin),
):
    """Delete a group."""
    app_state = get_app_state(request)

    success = await app_state.group_manager.delete_resource(group_name)
    if not success:
        raise GroupOperationError(f"Failed to delete group {group_name}")

    response = ResourceDeleteResponse(
        resource_type="group",
        resource_name=group_name,
        message=f"Group {group_name} deleted successfully",
    )

    logger.info(f"Admin {authenticated_user.user} deleted group {group_name}")
    return response
