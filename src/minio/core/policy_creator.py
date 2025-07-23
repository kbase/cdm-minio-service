"""
PolicyCreator module for creating new MinIO policy documents from scratch.

This module focuses on creating policies with organized sections.
For modifying existing policies, use PolicyBuilder.

POLICY TYPES CREATED:

1. USER HOME POLICIES (PolicyType.USER_HOME):
   - Policy Name: "user-home-policy-{username}"
   - Grants ADMIN access to user's personal warehouses:
     * s3a://{bucket}/users-sql-warehouse/{username}/ (for Spark tables)
     * s3a://{bucket}/users-general-warehouse/{username}/ (for general files)
   - Includes full read/write/delete permissions for user's personal workspace
   - Enables directory listing and bucket location access
   - SHARING OPERATIONS: Only paths within user home policies can be shared/unshared
     with other users or groups via the sharing API endpoints

2. USER SYSTEM POLICIES (PolicyType.USER_SYSTEM):
   - Policy Name: "user-system-policy-{username}"
   - Grants access to system resources defined in SYSTEM_RESOURCE_CONFIG:
     * Currently: s3a://cdm-spark-job-logs/spark-job-logs/{username}/ (WRITE access)
     * Future: Additional system resources as configured
   - Permission levels vary by resource (READ/WRITE/ADMIN)
   - User-scoped resources include username in path, global resources don't

3. GROUP POLICIES (PolicyType.GROUP_HOME):
   - Policy Name: "group-policy-{groupname}"
   - Grants WRITE access to group's shared workspace:
     * s3a://{bucket}/groups-general-warehouse/{groupname}/
   - Enables collaborative access for group members
   - Members inherit group permissions through policy attachment
"""

import logging
from typing import Dict, List

from ..models.minio_config import MinIOConfig
from ..models.policy import (
    PolicyPermissionLevel,
    PolicySectionType,
    PolicyStatement,
    PolicyType,
)

logger = logging.getLogger(__name__)

# Global system resource configuration
SYSTEM_RESOURCE_CONFIG = {
    # Spark-logs-related resources
    # Creates policy with access to s3a://cdm-spark-job-logs/spark-job-logs/username/
    "spark": {
        "bucket": "cdm-spark-job-logs",
        "base_prefix": "spark-job-logs",
        "user_scoped": True,  # Whether this resource is user-specific
        "permission_level": PolicyPermissionLevel.WRITE,
    },
    # Future system resources can be added here:
    #
    # Creates policy with access to s3a://cdm-task-service/task-service/
    # "task_service": {
    #     "bucket": "cdm-task-service",
    #     "base_prefix": "task-service",
    #     "user_scoped": False,
    #     "permission_level": PolicyPermissionLevel.READ,
    # },
    #
    # Creates policy with access to s3a://cdm-user-scratch/
    # "scratch": {
    #     "bucket": "cdm-user-scratch",
    #     "base_prefix": "",
    #     "user_scoped": False,
    #     "permission_level": PolicyPermissionLevel.WRITE,
    # },
}


class PolicyCreator:
    """
    Creator for building new MinIO policies from scratch.
    """

    def __init__(
        self,
        policy_type: PolicyType,
        target_name: str,
        config: MinIOConfig,
    ):
        """
        Initialize the PolicyCreator for building a new policy from scratch.

        Args:
            policy_type: Type of policy being created (USER_HOME, USER_SYSTEM, GROUP_HOME)
            target_name: Name of the target (username or group name)
            config: MinIO configuration for bucket and path information
        """

        self.policy_type = policy_type
        self.target_name = target_name
        self.system_config = SYSTEM_RESOURCE_CONFIG

        self.config = config
        # user warehouse for spark tables
        self.user_sql_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.users_sql_warehouse_prefix}/{self.target_name}"
        # user warehouse for general files
        self.user_general_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.users_general_warehouse_prefix}/{self.target_name}"
        # group warehouse for general files
        self.group_general_warehouse_path = f"s3a://{self.config.default_bucket}/{self.config.groups_general_warehouse_prefix}/{self.target_name}"

        # Internal section management with Dict[PolicySectionType, List[PolicyStatement]]
        self._sections: Dict[PolicySectionType, List[PolicyStatement]] = {
            PolicySectionType.GLOBAL_PERMISSIONS: [],
            PolicySectionType.BUCKET_ACCESS: [],
            PolicySectionType.READ_PERMISSIONS: [],
            PolicySectionType.WRITE_PERMISSIONS: [],
            PolicySectionType.DELETE_PERMISSIONS: [],
        }

    def _get_user_system_paths(
        self, username: str
    ) -> Dict[str, List[tuple[str, PolicyPermissionLevel]]]:
        """Get system resource paths and permission levels for a user using the global configuration."""
        user_paths = {}

        for _, resource_config in self.system_config.items():
            bucket = resource_config["bucket"]
            base_prefix = resource_config["base_prefix"]
            user_scoped = resource_config.get("user_scoped", True)
            permission_level = resource_config.get(
                "permission_level", PolicyPermissionLevel.WRITE
            )

            if user_scoped:
                # User-specific resource path
                path = f"{base_prefix}/{username}"
            else:
                # Global resource path (not user-specific)
                path = base_prefix

            path_with_permission = (path, permission_level)

            if bucket in user_paths:
                user_paths[bucket].append(path_with_permission)
            else:
                user_paths[bucket] = [path_with_permission]

        return user_paths
