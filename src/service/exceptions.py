"""
Custom exceptions for the MinIO Manager Service.
"""


class MinIOError(Exception):
    """
    The super class of all MinIO Manager Service related errors.
    """


class AuthenticationError(MinIOError):
    """
    Super class for authentication related errors.
    """


class MissingTokenError(AuthenticationError):
    """
    An error thrown when a token is required but absent.
    """


class InvalidAuthHeaderError(AuthenticationError):
    """
    An error thrown when an authorization header is invalid.
    """


class InvalidTokenError(AuthenticationError):
    """
    An error thrown when a user's token is invalid.
    """


class MissingRoleError(AuthenticationError):
    """
    An error thrown when a user is missing a required role.
    """


# ----- MinIO specific exceptions -----


class MinIOManagerError(MinIOError):
    """Base exception for MinIO Manager operations."""

    pass


class PolicyValidationError(MinIOManagerError):
    """Raised when policy content validation fails."""

    pass


class BucketValidationError(MinIOManagerError):
    """Raised when bucket name or configuration validation fails."""

    pass


class BucketOperationError(MinIOManagerError):
    """Raised when bucket operations fail."""

    pass


class UserOperationError(MinIOManagerError):
    """Raised when user operations fail."""

    pass


class GroupOperationError(MinIOManagerError):
    """Raised when group operations fail."""

    pass


class ValidationError(MinIOManagerError):
    """Raised when general validation fails."""

    pass


class ConnectionError(MinIOManagerError):
    """Raised when MinIO connection fails."""

    pass


class ConfigurationError(MinIOManagerError):
    """Raised when configuration is invalid."""

    pass
