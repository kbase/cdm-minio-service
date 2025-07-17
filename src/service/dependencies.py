"""
Dependencies for FastAPI dependency injection.
"""

import logging

from fastapi import Depends, HTTPException, status

from src.service.http_bearer import KBaseHTTPBearer
from src.service.kb_auth import AdminPermission, KBaseUser

logger = logging.getLogger(__name__)

# Initialize the KBase auth dependency for use in routes
auth = KBaseHTTPBearer()


def require_admin(user: KBaseUser = Depends(auth)) -> KBaseUser:
    """Dependency to ensure user has admin permissions."""
    if user.admin_perm != AdminPermission.FULL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required for this operation",
        )
    return user
