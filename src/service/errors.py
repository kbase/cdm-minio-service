"""
Custom error types for the MinIO Manager Service.
"""

# mostly copied from https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/errors.py

from enum import Enum


class ErrorType(Enum):
    """
    The type of an error, consisting of an error code and a brief string describing the type.
    :ivar error_code: an integer error code.
    :ivar error_type: a brief string describing the error type.
    """

    AUTHENTICATION_FAILED = (10000, "Authentication failed")
    """ A general authentication error. """

    NO_TOKEN = (10010, "No authentication token")
    """ No token was provided when required. """

    INVALID_TOKEN = (10020, "Invalid token")
    """ The token provided is not valid. """

    INVALID_AUTH_HEADER = (10030, "Invalid authentication header")
    """ The authentication header is not valid. """

    MISSING_ROLE = (10040, "Missing required role")
    """ The user is missing a required role. """

    # ----- MinIO specific error types -----
    MINIO_ERROR = (20000, "MinIO error")
    """ A general error related to MinIO. """

    MINIO_MANAGER_ERROR = (20010, "MinIO Manager error")
    """ A general error related to MinIO Manager operations. """

    POLICY_VALIDATION_ERROR = (20015, "Policy validation error")
    """ Policy content validation failed. """

    BUCKET_OPERATION_ERROR = (20020, "Bucket operation error")
    """ A bucket operation failed. """

    USER_OPERATION_ERROR = (20030, "User operation error")
    """ A user operation failed. """

    GROUP_OPERATION_ERROR = (20040, "Group operation error")
    """ A group operation failed. """

    CONNECTION_ERROR = (20050, "Connection error")
    """ MinIO connection failed. """

    CONFIGURATION_ERROR = (20060, "Configuration error")
    """ MinIO configuration is invalid. """

    MINIO_TABLE_NOT_FOUND = (20070, "MinIO table not found")
    """ The MinIO table was not found at the specified path. """

    MINIO_TABLE_OPERATION_ERROR = (20080, "MinIO table operation error")
    """ An operation on a MinIO table failed. """

    MINIO_QUERY_ERROR = (20090, "MinIO query error")
    """ There was an error executing a MinIO query. """

    REQUEST_VALIDATION_FAILED = (30010, "Request validation failed")
    """ A request to a service failed validation of the request. """

    def __init__(self, error_code, error_type):
        self.error_code = error_code
        self.error_type = error_type
