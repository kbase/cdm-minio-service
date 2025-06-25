from ...service.exceptions import BucketValidationError, ValidationError

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
    - Must not contain path separators to prevent security issues.

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

    if "/" in stripped_prefix or "\\" in stripped_prefix or ".." in stripped_prefix:
        raise ValidationError(
            f"Path prefix '{stripped_prefix}' cannot contain path separators ('/', '\\', '..')."
        )

    return stripped_prefix
