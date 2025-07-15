"""
Credential Management Routes for the MinIO Manager API.

This module provides the primary JupyterHub integration endpoints for credential
management. These are the core endpoints that JupyterHub calls to obtain temporary
MinIO credentials for users.
"""

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from ..minio.core.minio_client import MinIOClient
from ..minio.managers.user_manager import UserManager
from ..minio.models.minio_config import MinIOConfig
from ..service.arg_checkers import not_falsy
from ..service.dependencies import auth
from ..service.kb_auth import KBaseUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])


# ===== RESPONSE MODELS =====


class CredentialsResponse(BaseModel):
    """Primary response model for credential operations."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    username: Annotated[str, Field(description="Username", min_length=1)]
    access_key: Annotated[str, Field(description="MinIO access key (same as username)")]
    secret_key: Annotated[
        str, Field(description="MinIO secret key (fresh on each request)", min_length=8)
    ]


# ===== DEPENDENCY INJECTION =====


async def get_user_manager() -> UserManager:
    """Get initialized UserManager for credential operations."""
    config = MinIOConfig(
        endpoint=not_falsy(os.getenv("MINIO_ENDPOINT"), "MINIO_ENDPOINT"),
        access_key=not_falsy(os.getenv("MINIO_ROOT_USER"), "MINIO_ROOT_USER"),
        secret_key=not_falsy(os.getenv("MINIO_ROOT_PASSWORD"), "MINIO_ROOT_PASSWORD"),
    )

    client = MinIOClient(config)
    await client.initialize_session()

    return UserManager(client, config)


# ===== PRIMARY JUPYTERHUB ENDPOINTS =====


@router.get(
    "/",
    response_model=CredentialsResponse,
    summary="Get MinIO credentials",
    description="Primary endpoint for JupyterHub integration. Returns fresh MinIO credentials for the authenticated user. Creates user if they don't exist.",
)
async def get_credentials(
    authenticated_user: Annotated[KBaseUser, Depends(auth)],
):
    """Get fresh MinIO credentials for JupyterHub Spark integration."""
    user_manager: UserManager = await get_user_manager()

    try:
        username = authenticated_user.user

        # Check if user exists, create if not
        user_exists = await user_manager.resource_exists(username)
        if not user_exists:
            logger.info(f"Auto-creating user {username} for credential request")
            user_model = await user_manager.create_user(username=username)
            access_key, secret_key = user_model.access_key, user_model.secret_key
        else:
            # Get fresh credentials (rotates secret key)
            access_key, secret_key = await user_manager.get_or_rotate_user_credentials(
                username
            )

        response = CredentialsResponse(
            username=username,
            access_key=access_key,
            secret_key=secret_key,  # type: ignore
        )

        logger.info(f"Issued fresh credentials for user {username}")
        return response

    finally:
        await user_manager.client.close_session()
