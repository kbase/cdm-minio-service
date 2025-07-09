import re

from ...service.arg_checkers import not_falsy
from ...service.exceptions import (
    BucketValidationError,
    PolicyValidationError,
    UserOperationError,
    ValidationError,
)

# =============================================================================
# USERNAME VALIDATION
# =============================================================================


def validate_username(username: str) -> str:
    """
    Validate username for MinIO data governance service.

    Requirements for data governance:
    - Must be unique and trackable
    - Safe for file paths and policies
    - Compatible with MinIO user management

    Args:
        username: Username to validate

    Returns:
        str: Validated and normalized username

    Raises:
        UserOperationError: If username validation fails
    """
    username = not_falsy(username, "Username")
    username = username.strip()

    # Length constraints for MinIO compatibility
    if len(username) < 2 or len(username) > 64:
        raise UserOperationError("Username must be between 2 and 64 characters")

    # Character constraints - allow alphanumeric, dots, hyphens, underscores
    # These are safe for S3 paths and MinIO policies
    if not re.match(r"^[a-zA-Z0-9._-]+$", username):
        raise UserOperationError(
            "Username can only contain letters, numbers, periods, hyphens, and underscores"
        )

    # Must start and end with alphanumeric for S3 compatibility
    if not (username[0].isalnum() and username[-1].isalnum()):
        raise UserOperationError("Username must start and end with a letter or number")

    # No consecutive special characters to avoid path issues
    if re.search(r"[._-]{2,}", username):
        raise UserOperationError(
            "Username cannot contain consecutive special characters"
        )

    # Reserved usernames for data governance
    reserved_usernames = {
        "admin",
        "root",
        "system",
        "minio",
        "service",
        "backup",
        "guest",
        "anonymous",
        "public",
        "shared",
        "warehouse",
    }
    if username.lower() in reserved_usernames:
        raise UserOperationError(f"Username '{username}' is reserved for system use")

    return username


# =============================================================================
# BUCKET VALIDATION
# =============================================================================


# copied from CTS - https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/s3/paths.py#L98
def validate_bucket_name(bucket_name: str, index: int | None = None):
    """
    Validate an S3 bucket name.

    bucket_name - the bucket name to validate.
    index - the index of the bucket name in some external data structure.
        The index will be added to error messages.

    Returns a bucket name stripped of whitespace..
    """
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    i = f" at index {index}" if index is not None else ""
    bn = bucket_name.strip()
    if not bn:
        raise BucketValidationError(f"Bucket name{i} cannot be whitespace only")
    if len(bn) < 3 or len(bn) > 63:
        raise BucketValidationError(
            f"Bucket name{i} must be > 2 and < 64 characters: {bn}"
        )
    if "." in bn:
        raise BucketValidationError(
            f"Bucket{i} has `.` in the name which is unsupported: {bn}"
        )
    if bn.startswith("-") or bn.endswith("-"):
        raise BucketValidationError(
            f"Bucket name{i} cannot start or end with '-': {bn}"
        )
    if not bn.replace("-", "").isalnum() or not bn.isascii() or not bn.islower():
        raise BucketValidationError(
            f"Bucket name{i} may only contain '-' and lowercase ascii alphanumerics: {bn}"
        )
    return bn


# =============================================================================
# S3 PATH VALIDATION
# =============================================================================


def validate_path_prefix(prefix: str) -> str:
    """
    Validates a prefix to ensure it's a valid, non-empty path component.

    - Must not be empty or whitespace.
    - Must not contain path separators ('\\' and '..') to prevent security issues.

    Args:
        prefix: The prefix string to validate.

    Returns:
        The validated, stripped prefix.

    Raises:
        ValidationError: If the prefix is invalid.
    """
    if not prefix or not prefix.strip():
        raise ValidationError("Path prefix cannot be empty or contain only whitespace.")

    stripped_prefix = prefix.strip()

    if "\\" in stripped_prefix or ".." in stripped_prefix:
        raise ValidationError(
            f"Path prefix '{stripped_prefix}' cannot contain path separators ('\\', '..')."
        )

    return stripped_prefix


# =============================================================================
# POLICY VALIDATION
# =============================================================================


def validate_policy_name(policy_name: str) -> str:
    """
    Validate IAM policy name for data governance with comprehensive MinIO compatibility.

    Policy names in data governance should be:
    - Descriptive and meaningful
    - Compatible with MinIO policy system
    - Consistent naming convention
    - Safe for policy operations and attachment

    Args:
        policy_name: Policy name to validate

    Returns:
        str: Validated and normalized policy name

    Raises:
        PolicyValidationError: If policy name validation fails
    """
    policy_name = not_falsy(policy_name, "Policy name")
    policy_name = policy_name.strip()

    # Length constraints for MinIO compatibility (stricter than original for consistency)
    if len(policy_name) < 2 or len(policy_name) > 128:
        raise PolicyValidationError("Policy name must be between 2 and 128 characters")

    # Character constraints - allow alphanumeric, periods, hyphens, underscores
    if not re.match(r"^[a-zA-Z0-9._-]+$", policy_name):
        raise PolicyValidationError(
            "Policy name can only contain alphanumeric characters, "
            "periods (.), hyphens (-), and underscores (_)"
        )

    # Cannot start with a period for MinIO compatibility
    if policy_name[0] == ".":
        raise PolicyValidationError("Policy name cannot start with a period")

    # Check for reserved policy names (MinIO built-in policies)
    reserved_policies = {
        "readonly",
        "readwrite",
        "writeonly",
        "diagnostics",
        "public",
        "consoleAdmin",
    }
    if policy_name in reserved_policies:
        raise PolicyValidationError(f"'{policy_name}' is a reserved policy name")

    # Avoid names that could be confused with system policies
    if policy_name.startswith("arn:"):
        raise PolicyValidationError("Policy name cannot start with 'arn:'")

    # Recommended naming patterns for data governance (informational only)
    valid_prefixes = ["user-", "group-"]
    if not any(policy_name.lower().startswith(prefix) for prefix in valid_prefixes):
        raise PolicyValidationError("Policy name should start with 'user-' or 'group-'")

    return policy_name
