import os
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

CDM_DEFAULT_BUCKET = os.getenv("CDM_DEFAULT_BUCKET", "cdm-lake")
CDM_DEFAULT_WAREHOUSE_PREFIX = os.getenv("CDM_DEFAULT_WAREHOUSE_PREFIX", "warehouse")


class MinIOConfig(BaseModel):
    """
    MinIO configuration model.

    This model contains the essential configuration needed for MinIO operations.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    # Core connection settings
    endpoint: Annotated[
        str,
        Field(
            description="MinIO server endpoint URL",
            examples=["http://localhost:9002", "https://minio.example.com"],
        ),
    ]
    access_key: Annotated[
        str,
        Field(
            description="MinIO access key for authentication",
            examples=["minio", "admin"],
        ),
    ]
    secret_key: Annotated[
        str,
        Field(
            description="MinIO secret key for authentication",
            examples=["minio123", "password123"],
        ),
    ]
    secure: Annotated[
        bool, Field(default=False, description="Whether to use HTTPS for connections")
    ] = False

    # Application settings
    default_bucket: Annotated[
        str,
        Field(
            default=CDM_DEFAULT_BUCKET,
            description="Default bucket for system operations",
            examples=[CDM_DEFAULT_BUCKET],
        ),
    ] = CDM_DEFAULT_BUCKET

    warehouse_prefix: Annotated[
        str,
        Field(
            default=CDM_DEFAULT_WAREHOUSE_PREFIX,
            description="Prefix for user warehouse directories",
            examples=[CDM_DEFAULT_WAREHOUSE_PREFIX],
        ),
    ] = CDM_DEFAULT_WAREHOUSE_PREFIX
