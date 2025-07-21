"""
Data Sharing Routes for the MinIO Manager API.

This module provides the core data governance functionality for sharing and
unsharing data between users and groups.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..minio.utils.validators import validate_s3_path
from ..service.app_state import get_app_state
from ..service.dependencies import auth
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sharing", tags=["sharing"])


# ===== REQUEST MODELS =====


class ShareRequest(BaseModel):
    """Request model for sharing data with users or groups."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: Annotated[
        str,
        Field(
            description="S3 path to share",
            examples=[
                "s3a://cdm-lake/users-general-warehouse/john/datasets/experiment1/"
            ],
            min_length=1,
        ),
    ]
    with_users: Annotated[
        list[str],
        Field(default_factory=list, description="List of usernames to share with"),
    ]
    with_groups: Annotated[
        list[str],
        Field(default_factory=list, description="List of group names to share with"),
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate S3 path format."""
        return validate_s3_path(v)


# ===== RESPONSE MODELS =====


class ShareResponse(BaseModel):
    """Response model for sharing operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    path: Annotated[str, Field(description="Path that was shared")]
    shared_with_users: Annotated[
        list[str], Field(description="Users successfully shared with")
    ]
    shared_with_groups: Annotated[
        list[str], Field(description="Groups successfully shared with")
    ]
    success_count: Annotated[int, Field(description="Total successful shares", ge=0)]
    errors: Annotated[
        list[str], Field(default_factory=list, description="Any errors encountered")
    ]
    shared_by: Annotated[
        str, Field(description="User who performed the sharing", min_length=1)
    ]
    shared_at: Annotated[datetime, Field(description="When sharing was performed")]


# ===== SHARING ENDPOINTS =====


@router.post(
    "/share",
    response_model=ShareResponse,
    status_code=status.HTTP_200_OK,
    summary="Share data path",
    description="Share an S3 path with specified users and/or groups. Only path owners can share their data.",
)
async def share_data(
    share_request: Annotated[ShareRequest, Body(description="Sharing configuration")],
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
    request: Request,
):
    """Share a data path with specified users or groups."""
    app_state = get_app_state(request)

    username = authenticated_user.user

    # Perform the sharing operation
    result = await app_state.sharing_manager.share_path(
        path=share_request.path,
        requesting_user=username,
        with_users=share_request.with_users,
        with_groups=share_request.with_groups,
    )

    response = ShareResponse(
        path=share_request.path,
        shared_with_users=result.shared_with_users,
        shared_with_groups=result.shared_with_groups,
        success_count=result.success_count,
        errors=result.errors,
        shared_by=username,
        shared_at=datetime.now(),
    )

    logger.info(
        f"User {username} shared {share_request.path} with "
        f"{len(result.shared_with_users)} users and {len(result.shared_with_groups)} groups"
    )

    return response
