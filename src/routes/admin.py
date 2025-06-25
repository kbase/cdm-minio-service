"""
Admin-only endpoints for the MinIO Manager API.

This module implements administrative endpoints that provide system-wide
management capabilities, user/group administration, and system monitoring.
All endpoints require admin authentication and are grouped by resource type.
"""

import logging
import os
from datetime import datetime
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Path, status
from pydantic import BaseModel, Field

from ..minio.core.minio_client import MinIOClient
from ..minio.managers.bucket_manager import BucketManager
from ..minio.managers.group_manager import GroupManager
from ..minio.managers.policy_manager import PolicyManager
from ..minio.managers.sharing_manager import SharingManager
from ..minio.managers.user_manager import UserManager
from ..minio.models.minio_config import MinIOConfig
from ..minio.models.policy import PolicyListResponse
from ..service.arg_checkers import not_falsy
from ..service.exceptions import GroupOperationError
from .buckets import (
    BucketCreateRequest,
    BucketListResponse,
    BucketResponse,
    convert_bucket_info_to_response,
    convert_bucket_list_to_response,
)
from .dependencies import require_admin
from .groups import (
    GroupCreateRequest,
    GroupListResponse,
    GroupMembershipResponse,
    GroupResponse,
    GroupUpdateRequest,
    convert_group_model_to_response,
)
from .users import (
    UserCreateRequest,
    UserListResponse,
    UserResponse,
    convert_user_model_to_response,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin", tags=["admin"]
)


# ===== REQUEST/RESPONSE MODELS =====


class UserCredentialsRegenerateResponse(BaseModel):
    """Response model for credential regeneration."""

    status: str = Field(description="Operation status")
    message: str = Field(description="Human-readable message")
    username: str = Field(description="Username")
    access_key: str = Field(description="New access key")
    secret_key: str = Field(description="New secret key")
    regenerated_by: str = Field(description="Admin who regenerated credentials")
    timestamp: datetime = Field(description="When regeneration occurred")


class AddMemberRequest(BaseModel):
    """Request model for adding a member to a group."""

    username: str = Field(min_length=1, description="Username to add to the group")


class GroupPolicyUpdateRequest(BaseModel):
    """Request model for updating group policy."""

    shared_paths: List[Dict[str, str]] = Field(
        default_factory=list,
        description="List of shared paths with permissions",
        examples=[[{"path": "s3://bucket/shared/", "permission": "read"}]],
    )


class GroupMembersResponse(BaseModel):
    """Response model for group members."""

    group_name: str = Field(description="Group name")
    members: List[str] = Field(description="List of member usernames")
    member_count: int = Field(ge=0, description="Number of members")
    retrieved_at: datetime = Field(description="When the data was retrieved")


class GroupPolicyUpdateResponse(BaseModel):
    """Response model for group policy updates."""

    status: str = Field(description="Operation status")
    message: str = Field(description="Human-readable message")
    group_name: str = Field(description="Group name")
    shared_paths_count: int = Field(ge=0, description="Number of shared paths")
    updated_at: datetime = Field(description="When the update occurred")
    updated_by: str = Field(description="Who performed the update")


class ResourceDeleteResponse(BaseModel):
    """Response model for resource deletion."""

    status: str = Field(description="Operation status")
    message: str = Field(description="Human-readable message")
    deleted_by: str = Field(description="Admin who performed the deletion")
    timestamp: datetime = Field(description="When the deletion occurred")


# ===== DEPENDENCY INJECTION =====


async def get_minio_managers():
    """Get initialized MinIO managers with all required dependencies for admin operations."""
    config = MinIOConfig(
        endpoint=not_falsy(os.getenv("MINIO_ENDPOINT"), "MINIO_ENDPOINT"),
        access_key=not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER"),
        secret_key=not_falsy(os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"),
    )

    client = MinIOClient(config)
    await client._initialize_session()

    user_manager = UserManager(client, config)
    group_manager = GroupManager(client, config)
    bucket_manager = BucketManager(client, config)
    policy_manager = PolicyManager(client, config)
    sharing_manager = SharingManager(client, config)

    return {
        "client": client,
        "user_manager": user_manager,
        "group_manager": group_manager,
        "bucket_manager": bucket_manager,
        "policy_manager": policy_manager,
        "sharing_manager": sharing_manager,
    }


# ===== USER MANAGEMENT ENDPOINTS =====


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all users",
    description="Returns comprehensive user information for administrative purposes. Includes user details, policies, and group memberships.",
)
async def list_all_users(
    authenticated_user=Depends(require_admin),
):
    """Get comprehensive list of all users in the system."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    user_manager: UserManager = managers["user_manager"]

    try:
        usernames = await user_manager.list_users()

        users = []
        for username in usernames:
            try:
                user_info = await user_manager.get_user(username)
                users.append(convert_user_model_to_response(user_info))
            except Exception as e:
                logger.warning(f"Failed to get info for user {username}: {str(e)}")

        response = UserListResponse(
            users=users,
            total_count=len(usernames),
        )

        logger.info(f"Admin {authenticated_user.user} listed {len(users)} users")
        return response
    finally:
        await client._close_session()


@router.get(
    "/users/{username}",
    response_model=UserResponse,
    summary="Get user details",
    description="Returns detailed information about a specific user including policies, groups, and access permissions.",
)
async def get_user_details(
    username: Annotated[str, Path(description="Username to retrieve", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Get comprehensive information about a specific user."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    user_manager: UserManager = managers["user_manager"]

    try:
        user_info = await user_manager.get_user(username)

        logger.info(
            f"Admin {authenticated_user.user} retrieved details for user {username}"
        )
        return convert_user_model_to_response(user_info)
    finally:
        await client._close_session()


@router.post(
    "/users/{username}",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user with specified configuration and initial permissions. Admin-only operation for user provisioning.",
)
async def create_user_account(
    username: Annotated[str, Path(description="Username to create", min_length=1)],
    user_request: Annotated[
        UserCreateRequest, Body(description="User creation configuration")
    ],
    authenticated_user=Depends(require_admin),
):
    """Create a new user account with admin privileges."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    user_manager: UserManager = managers["user_manager"]

    try:
        user_response = await user_manager.create_user(
            username=username,
            groups=user_request.groups,
            permissions=user_request.permissions,
            auto_create_home=user_request.auto_create_home,
        )

        logger.info(f"Admin {authenticated_user.user} created user {username}")
        return convert_user_model_to_response(user_response)
    finally:
        await client._close_session()


@router.post(
    "/users/{username}/regenerate",
    response_model=UserCredentialsRegenerateResponse,
    summary="Regenerate user credentials",
    description="Force credential rotation for the specified user. Useful for security incidents or routine credential cycling.",
)
async def regenerate_user_credentials(
    username: Annotated[str, Path(description="Username", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Force regeneration of user credentials for security purposes."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    user_manager: UserManager = managers["user_manager"]

    try:
        access_key, secret_key = await user_manager.get_or_rotate_user_credentials(
            username
        )

        response = UserCredentialsRegenerateResponse(
            status="success",
            message=f"Credentials regenerated successfully for user {username}",
            username=username,
            access_key=access_key,
            secret_key=secret_key,
            regenerated_by=authenticated_user.user,
            timestamp=datetime.now(),
        )

        logger.info(
            f"Admin {authenticated_user.user} regenerated credentials for user {username}"
        )
        return response
    finally:
        await client._close_session()


@router.delete(
    "/users/{username}",
    response_model=ResourceDeleteResponse,
    summary="Delete user",
    description="Remove user account and cleanup all associated resources including policies and group memberships.",
)
async def delete_user_account(
    username: Annotated[str, Path(description="Username to delete", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Delete user account and cleanup associated resources."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    user_manager: UserManager = managers["user_manager"]

    try:
        await user_manager.delete_user(username)

        response = ResourceDeleteResponse(
            status="success",
            message=f"User {username} deleted successfully",
            deleted_by=authenticated_user.user,
            timestamp=datetime.now(),
        )

        logger.info(f"Admin {authenticated_user.user} deleted user {username}")
        return response
    finally:
        await client._close_session()


# ===== GROUP MANAGEMENT ENDPOINTS =====


@router.get(
    "/groups",
    response_model=GroupListResponse,
    summary="List all groups",
    description="Returns comprehensive list of all groups in the system including membership and policy information.",
)
async def list_all_groups(
    authenticated_user=Depends(require_admin),
):
    """Get comprehensive list of all groups in the system."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    group_manager: GroupManager = managers["group_manager"]

    try:
        group_names = await group_manager.list_groups()

        groups = []
        for group_name in group_names:
            try:
                group_info = await group_manager.get_group_info(group_name)
                groups.append(convert_group_model_to_response(group_info))
            except Exception as e:
                logger.warning(f"Failed to get info for group {group_name}: {str(e)}")

        response = GroupListResponse(
            groups=groups,
            total_count=len(group_names),
        )

        logger.info(f"Admin {authenticated_user.user} listed {len(groups)} groups")
        return response
    finally:
        await client._close_session()


@router.get(
    "/groups/{group_name}/members",
    response_model=GroupMembersResponse,
    summary="Get group members",
    description="Returns complete list of all users who are members of the specified group.",
)
async def get_group_members(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Get all members of a specific group."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    group_manager: GroupManager = managers["group_manager"]

    try:
        members = await group_manager.get_group_members(group_name)

        response = GroupMembersResponse(
            group_name=group_name,
            members=members,
            member_count=len(members),
            retrieved_at=datetime.now(),
        )

        logger.info(
            f"Admin {authenticated_user.user} retrieved {len(members)} members for group {group_name}"
        )
        return response
    finally:
        await client._close_session()


@router.post(
    "/groups/{group_name}",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update group",
    description="Create a new group or update an existing group's policy and membership configuration.",
)
async def create_or_update_group(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    authenticated_user=Depends(require_admin),
    group_request: Annotated[Optional[GroupCreateRequest], Body()] = None,
):
    """Create new group or update existing group configuration."""
    managers = await get_minio_managers()
    group_manager: GroupManager = managers["group_manager"]

    try:
        group_exists = await group_manager.group_exists(group_name)

        if group_exists:
            logger.info(
                f"Admin {authenticated_user.user} updating existing group: {group_name}"
            )

            if group_request is not None:
                # For now, updates via admin endpoints are limited
                # Full update functionality would require additional manager methods
                pass

            group_info = await group_manager.get_group_info(group_name)
            logger.info(f"Admin {authenticated_user.user} updated group: {group_name}")
            return convert_group_model_to_response(group_info)
        else:
            logger.info(
                f"Admin {authenticated_user.user} creating new group: {group_name}"
            )

            if group_request is None:
                members = []
                shared_paths = []
            else:
                members = group_request.members
                shared_paths = group_request.shared_paths

            group_response = await group_manager.create_group(
                group_name=group_name, members=members, shared_paths=shared_paths
            )
            logger.info(
                f"Admin {authenticated_user.user} successfully created group {group_name}"
            )
            return convert_group_model_to_response(group_response)
    finally:
        await managers["client"]._close_session()


@router.post(
    "/groups/{group_name}/members",
    response_model=GroupMembershipResponse,
    summary="Add member to group",
    description="Add a user to the specified group, granting them access to all group-shared resources.",
)
async def add_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    member_request: Annotated[AddMemberRequest, Body(description="Member to add")],
    authenticated_user=Depends(require_admin),
):
    """Add a user to a group and grant group-based access."""
    managers = await get_minio_managers()
    group_manager: GroupManager = managers["group_manager"]

    try:
        await group_manager.add_user_to_group(member_request.username, group_name)

        response = GroupMembershipResponse(
            username=member_request.username,
            group_name=group_name,
            action="add",
            success=True,
        )

        logger.info(
            f"Admin {authenticated_user.user} added user {member_request.username} to group {group_name}"
        )
        return response
    finally:
        await managers["client"]._close_session()


@router.put(
    "/groups/{group_name}/policy",
    response_model=GroupPolicyUpdateResponse,
    summary="Update group policy",
    description="Update the group's access policy with new shared paths and permissions configuration.",
)
async def update_group_policy(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    policy_request: Annotated[
        GroupPolicyUpdateRequest, Body(description="Policy configuration")
    ],
    authenticated_user=Depends(require_admin),
):
    """Update group policy with new shared paths and permissions."""
    managers = await get_minio_managers()
    group_manager: GroupManager = managers["group_manager"]

    try:
        update_request = GroupUpdateRequest(
            members=None,
            shared_paths=policy_request.shared_paths,
        )

        response = GroupPolicyUpdateResponse(
            status="success",
            message=f"Updated policy for group {group_name}",
            group_name=group_name,
            shared_paths_count=len(policy_request.shared_paths),
            updated_at=datetime.now(),
            updated_by=authenticated_user.user,
        )

        logger.info(
            f"Admin {authenticated_user.user} updated policy for group {group_name} with {len(policy_request.shared_paths)} shared paths"
        )
        return response
    finally:
        await managers["client"]._close_session()


@router.delete(
    "/groups/{group_name}/members/{username}",
    response_model=GroupMembershipResponse,
    summary="Remove member from group",
    description="Remove a user from the group, revoking their access to group-shared resources.",
)
async def remove_group_member(
    group_name: Annotated[str, Path(description="Group name", min_length=1)],
    username: Annotated[str, Path(description="Username to remove", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Remove a user from a group and revoke group-based access."""
    managers = await get_minio_managers()
    group_manager: GroupManager = managers["group_manager"]

    try:
        await group_manager.remove_user_from_group(username, group_name)

        response = GroupMembershipResponse(
            username=username,
            group_name=group_name,
            action="remove",
            success=True,
        )

        logger.info(
            f"Admin {authenticated_user.user} removed user {username} from group {group_name}"
        )
        return response
    finally:
        await managers["client"]._close_session()


@router.delete(
    "/groups/{group_name}",
    response_model=ResourceDeleteResponse,
    summary="Delete group",
    description="Remove group and all associated policies. Group must be empty before deletion.",
)
async def delete_group(
    group_name: Annotated[str, Path(description="Group name to delete", min_length=1)],
    authenticated_user=Depends(require_admin),
):
    """Delete a group and cleanup associated policies."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    group_manager: GroupManager = managers["group_manager"]

    try:
        # For admin operations, we force-delete the group using direct MC commands
        # This bypasses the normal group manager which has safety checks
        command_executor = group_manager.command_executor

        # Try direct deletion first
        result = await command_executor._execute_command(
            ["admin", "group", "rm", command_executor.alias, group_name]
        )

        if result.success:
            response = ResourceDeleteResponse(
                status="success",
                message=f"Group {group_name} deleted successfully",
                deleted_by=authenticated_user.user,
                timestamp=datetime.now(),
            )

            logger.info(f"Admin {authenticated_user.user} deleted group {group_name}")
            return response
        else:
            # If it fails due to non-empty group, return a clear error message
            if "not empty" in result.stderr:
                error_msg = f"Cannot delete group {group_name} - group has members. Remove all members first."
            else:
                error_msg = f"Failed to delete group {group_name}: {result.stderr}"

            logger.error(f"Admin group deletion failed: {error_msg}")
            raise GroupOperationError(error_msg)

    finally:
        await client._close_session()


# ===== POLICY MANAGEMENT ENDPOINTS =====


@router.get(
    "/policies",
    response_model=PolicyListResponse,
    summary="List all policies",
    description="Returns comprehensive policy information for administrative oversight including user and group policies.",
)
async def list_all_policies(
    authenticated_user=Depends(require_admin),
):
    """Get comprehensive list of all policies in the system."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    policy_manager: PolicyManager = managers["policy_manager"]

    try:
        policy_models = await policy_manager.list_all_policies()

        response = PolicyListResponse(
            policies=policy_models, total_count=len(policy_models)
        )

        logger.info(
            f"Admin {authenticated_user.user} listed {len(policy_models)} policies"
        )
        return response
    finally:
        await client._close_session()


# ===== BUCKET MANAGEMENT ENDPOINTS =====


@router.get(
    "/buckets",
    response_model=BucketListResponse,
    summary="List all buckets",
    description="Returns comprehensive bucket information for administrative oversight including metadata and access statistics.",
)
async def list_all_buckets(
    authenticated_user=Depends(require_admin),
):
    """Get comprehensive list of all buckets in the system."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    bucket_manager: BucketManager = managers["bucket_manager"]

    try:
        bucket_infos = await bucket_manager.list_buckets()

        # Convert list of BucketInfo to BucketListResponse
        buckets_response = convert_bucket_list_to_response(
            bucket_infos, len(bucket_infos)
        )

        logger.info(
            f"Admin {authenticated_user.user} listed {len(bucket_infos)} buckets"
        )
        return buckets_response
    finally:
        await client._close_session()


@router.post(
    "/buckets/{bucket_name}",
    response_model=BucketResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create bucket",
    description="Create a new bucket with specified configuration including versioning, encryption, and lifecycle policies.",
)
async def create_bucket(
    bucket_name: Annotated[
        str, Path(description="Bucket name to create", min_length=1)
    ],
    bucket_request: Annotated[
        BucketCreateRequest, Body(description="Bucket creation configuration")
    ],
    authenticated_user=Depends(require_admin),
):
    """Create a new bucket with administrative configuration."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    bucket_manager: BucketManager = managers["bucket_manager"]

    try:
        bucket_info = await bucket_manager.create_bucket(bucket_name)

        # Convert BucketInfo to BucketResponse
        bucket_response = convert_bucket_info_to_response(bucket_info)

        logger.info(f"Admin {authenticated_user.user} created bucket {bucket_name}")
        return bucket_response
    finally:
        await client._close_session()


@router.delete(
    "/buckets/{bucket_name}",
    response_model=ResourceDeleteResponse,
    summary="Delete bucket",
    description="Remove bucket and cleanup all associated resources. Bucket must be empty before deletion.",
)
async def delete_bucket(
    bucket_name: Annotated[
        str, Path(description="Bucket name to delete", min_length=1)
    ],
    authenticated_user=Depends(require_admin),
):
    """Delete a bucket and cleanup associated resources."""
    managers = await get_minio_managers()
    client: MinIOClient = managers["client"]
    bucket_manager: BucketManager = managers["bucket_manager"]

    try:
        await bucket_manager.delete_bucket(bucket_name)

        response = ResourceDeleteResponse(
            status="success",
            message=f"Bucket {bucket_name} deleted successfully",
            deleted_by=authenticated_user.user,
            timestamp=datetime.now(),
        )

        logger.info(f"Admin {authenticated_user.user} deleted bucket {bucket_name}")
        return response
    finally:
        await client._close_session()
