import os
from typing import Annotated

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from ...service.exceptions import BucketValidationError, ValidationError
from ..utils.validators import validate_bucket_name, validate_path_prefix

CDM_DEFAULT_BUCKET = os.getenv("CDM_DEFAULT_BUCKET", "cdm-lake")

# Default warehouse prefix for users - this is where user created DB/tables are stored
# e.g. s3a://cdm-lake/users-warehouse/{username}
CDM_DEFAULT_USERS_WAREHOUSE_PREFIX = os.getenv(
    "CDM_DEFAULT_USERS_WAREHOUSE_PREFIX", "users-warehouse"
)
# Default warehouse prefix for groups - this is used for group shared data
# e.g. s3a://cdm-lake/groups-warehouse/{group_name}
CDM_DEFAULT_GROUPS_WAREHOUSE_PREFIX = os.getenv(
    "CDM_DEFAULT_GROUPS_WAREHOUSE_PREFIX", "groups-warehouse"
)


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
        AnyHttpUrl,
        Field(
            description="MinIO server endpoint URL",
            examples=["http://localhost:9002", "https://minio.example.com"],
        ),
    ]
    access_key: Annotated[
        str,
        Field(
            min_length=1,
            description="MinIO access key for authentication",
            examples=["minio", "admin"],
        ),
    ]
    secret_key: Annotated[
        str,
        Field(
            min_length=1,
            description="MinIO secret key for authentication",
            examples=["minio123", "password123"],
        ),
    ]
    secure: Annotated[
        bool, Field(default=True, description="Whether to use HTTPS for connections")
    ] = True

    # Application settings
    default_bucket: Annotated[
        str,
        Field(
            min_length=3,
            max_length=63,
            default=CDM_DEFAULT_BUCKET,
            description="Default bucket for system operations",
            examples=[CDM_DEFAULT_BUCKET],
        ),
    ] = CDM_DEFAULT_BUCKET

    users_warehouse_prefix: Annotated[
        str,
        Field(
            min_length=1,
            max_length=1024,
            default=CDM_DEFAULT_USERS_WAREHOUSE_PREFIX,
            description="Prefix for user warehouse directories",
            examples=[CDM_DEFAULT_USERS_WAREHOUSE_PREFIX],
        ),
    ] = CDM_DEFAULT_USERS_WAREHOUSE_PREFIX

    groups_warehouse_prefix: Annotated[
        str,
        Field(
            min_length=1,
            max_length=1024,
            default=CDM_DEFAULT_GROUPS_WAREHOUSE_PREFIX,
            description="Prefix for group warehouse directories",
            examples=[CDM_DEFAULT_GROUPS_WAREHOUSE_PREFIX],
        ),
    ] = CDM_DEFAULT_GROUPS_WAREHOUSE_PREFIX

    @field_validator("users_warehouse_prefix")
    @classmethod
    def validate_users_warehouse_prefix_str(cls, v: str) -> str:
        """Validate the users_warehouse_prefix using the project's custom validator."""
        try:
            return validate_path_prefix(v)
        except ValidationError as e:
            raise ValueError(str(e))

    @field_validator("groups_warehouse_prefix")
    @classmethod
    def validate_groups_warehouse_prefix_str(cls, v: str) -> str:
        """Validate the groups_warehouse_prefix using the project's custom validator."""
        try:
            return validate_path_prefix(v)
        except ValidationError as e:
            raise ValueError(str(e))

    @field_validator("default_bucket")
    @classmethod
    def validate_default_bucket_name(cls, v: str) -> str:
        """Validate the default_bucket name using the project's custom validator."""
        try:
            return validate_bucket_name(v)
        except BucketValidationError as e:
            raise ValueError(str(e))
