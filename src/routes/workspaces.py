"""
Workspace Management Routes for the MinIO Manager API.

This module provides user workspace management including personal directories,
group spaces, and workspace organization. Focuses on the user experience of
organizing and managing their data storage.
"""

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, ConfigDict, Field

from ..minio.core.minio_client import MinIOClient
from ..minio.managers.group_manager import GroupManager
from ..minio.managers.policy_manager import PolicyManager
from ..minio.managers.user_manager import UserManager
from ..minio.models.minio_config import MinIOConfig
from ..minio.models.user import UserModel
from ..service.arg_checkers import not_falsy
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


# ===== DEPENDENCY INJECTION =====


async def get_workspace_managers():
    """Get initialized managers for workspace operations."""
    config = MinIOConfig(
        endpoint=not_falsy(os.getenv("MINIO_ENDPOINT"), "MINIO_ENDPOINT"),
        access_key=not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER"),
        secret_key=not_falsy(os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"),
    )

    client = MinIOClient(config)
    await client._initialize_session()

    user_manager = UserManager(client, config)
    group_manager = GroupManager(client, config)
    policy_manager = PolicyManager(client, config)

    return {
        "client": client,
        "user_manager": user_manager,
        "group_manager": group_manager,
        "policy_manager": policy_manager,
    }


# ===== USER WORKSPACE ENDPOINTS =====


@router.get(
    "/me",
    response_model=UserModel,
    summary="Get my workspace",
    description="Get user information for the authenticated user.",
)
async def get_my_workspace(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Get user information for the authenticated user."""
    managers = await get_workspace_managers()
    user_manager: UserManager = managers["user_manager"]

    try:
        username = authenticated_user.user
        user_info = await user_manager.get_user(username)

        logger.info(f"Retrieved workspace information for user {username}")
        return user_info

    finally:
        await user_manager.client._close_session()


@router.get(
    "/me/groups",
    response_model=UserGroupsResponse,
    summary="Get my groups",
    description="Get list of groups the authenticated user belongs to.",
)
async def get_my_groups(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Get all groups the authenticated user belongs to."""
    managers = await get_workspace_managers()
    group_manager: GroupManager = managers["group_manager"]

    try:
        username = authenticated_user.user

        # Get user's groups using GroupManager
        user_groups = await group_manager.get_user_groups(username)

        response = UserGroupsResponse(
            username=username,
            groups=user_groups,
            group_count=len(user_groups),
        )

        logger.info(f"Retrieved groups for user {username}")
        return response

    finally:
        await managers["client"]._close_session()


@router.get(
    "/me/groups/{group_name}",
    response_model=GroupWorkspaceResponse,
    summary="Get group workspace",
    description="Get workspace information for a specific group including shared areas and member access.",
)
async def get_group_workspace(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Get workspace information for a group."""
    managers = await get_workspace_managers()
    group_manager: GroupManager = managers["group_manager"]
    policy_manager: PolicyManager = managers["policy_manager"]

    try:
        username = authenticated_user.user

        # Check if user is a member of the group
        is_member = await group_manager.is_user_in_group(username, group_name)
        if not is_member:
            raise MinIOManagerError("User is not a member of the group")
        # Get group information
        group_info = await group_manager.get_group_info(group_name)
        group_policy = await policy_manager.get_group_policy(group_name)
        group_accessible_paths = policy_manager.get_accessible_paths_from_policy(
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

    finally:
        await managers["client"]._close_session()
