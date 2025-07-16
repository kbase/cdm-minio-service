"""
Workspace Management Routes for the MinIO Manager API.

This module provides user workspace management including personal directories,
group spaces, and workspace organization. Focuses on the user experience of
organizing and managing their data storage.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, Field

from ..minio.models.user import UserModel
from ..service.app_state import get_app_state
from ..service.dependencies import auth
from ..service.exceptions import MinIOManagerError
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


# ===== RESPONSE MODELS =====


class GroupWorkspaceResponse(BaseModel):
    """Response model for group workspace information."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    group_name: Annotated[str, Field(description="Group name", min_length=1)]
    members: Annotated[list[str], Field(description="Group members")]
    member_count: Annotated[int, Field(description="Number of members", ge=0)]
    accessible_paths: Annotated[
        list[str], Field(description="Group's accessible paths")
    ]


class UserGroupsResponse(BaseModel):
    """Response model for user's group memberships."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    groups: Annotated[list[str], Field(description="Groups user belongs to")]
    group_count: Annotated[int, Field(description="Number of groups", ge=0)]


# ===== USER WORKSPACE ENDPOINTS =====


@router.get(
    "/me",
    response_model=UserModel,
    summary="Get my workspace",
    description="Get user information for the authenticated user.",
)
async def get_my_workspace(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get user information for the authenticated user."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    user_info = await app_state.user_manager.get_user(username)

    logger.info(f"Retrieved workspace information for user {username}")
    return user_info


@router.get(
    "/me/groups",
    response_model=UserGroupsResponse,
    summary="Get my groups",
    description="Get list of groups the authenticated user belongs to.",
)
async def get_my_groups(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get all groups the authenticated user belongs to."""
    app_state = get_app_state(request)

    username = authenticated_user.user
    user_groups = await app_state.group_manager.get_user_groups(username)

    response = UserGroupsResponse(
        username=username,
        groups=user_groups,
        group_count=len(user_groups),
    )

    logger.info(f"Retrieved groups for user {username}")
    return response


@router.get(
    "/me/groups/{group_name}",
    response_model=GroupWorkspaceResponse,
    summary="Get group workspace",
    description="Get workspace information for a specific group including shared areas and member access.",
)
async def get_group_workspace(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Get workspace information for a group."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Check if user is a member of the group
    is_member = await app_state.group_manager.is_user_in_group(username, group_name)
    if not is_member:
        raise MinIOManagerError("User is not a member of the group")
    # Get group information
    group_info = await app_state.group_manager.get_group_info(group_name)
    group_policy = await app_state.policy_manager.get_group_policy(group_name)
    group_accessible_paths = app_state.policy_manager.get_accessible_paths_from_policy(
        group_policy
    )

    response = GroupWorkspaceResponse(
        group_name=group_name,
        members=group_info.members,
        member_count=len(group_info.members),
        accessible_paths=group_accessible_paths,
    )

    logger.info(f"Retrieved group workspace for {group_name} by user {username}")
    return response
