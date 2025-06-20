"""
Configuration settings for the CDM MCP Server.

This service enables AI assistants to interact with Delta Lake tables stored in MinIO through Spark,
implementing the Model Context Protocol (MCP) for natural language data operations.
"""

import logging
import os
from functools import lru_cache

from pydantic import BaseModel, Field

APP_VERSION = "0.1.0"
# SERVICE_ROOT_PATH = "/apis/mcp"
SERVICE_ROOT_PATH = ""

class Settings(BaseModel):
    """
    Application settings for the MinIO Manager Service.
    """

    app_name: str = "CDM MCP Server"
    app_description: str = (
        "FastAPI service for AI assistants to interact with Delta Lake tables via Spark"
    )
    api_version: str = APP_VERSION
    service_root_path: str = SERVICE_ROOT_PATH
    log_level: str = Field(
        default=os.getenv("LOG_LEVEL", "INFO"),
        description="Logging level for the application",
    )
    
    # MinIO Configuration
    minio_endpoint: str = Field(
        default=os.getenv("MINIO_ENDPOINT", "http://localhost:9000"),
        description="MinIO server endpoint",
    )
    minio_root_user: str = Field(
        default=os.getenv("MINIO_ROOT_USER", "minioadmin"),
        description="MinIO root username",
    )
    minio_root_password: str = Field(
        default=os.getenv("MINIO_ROOT_PASSWORD", "minioadmin"),
        description="MinIO root password",
    )
    
    # KBase Authentication Configuration
    kbase_auth_url: str = Field(
        default=os.getenv("KBASE_AUTH_URL", "https://ci.kbase.us/services/auth/"),
        description="KBase authentication service URL",
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get the application settings.

    Uses lru_cache to avoid loading the settings for every request.
    """
    return Settings()


# Global settings instance for convenience
settings = get_settings()


def configure_logging():
    """Configure logging for the application."""
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if settings.log_level.upper() not in logging.getLevelNamesMapping():
        logging.warning(
            "Unrecognized log level '%s'. Falling back to 'INFO'.",
            settings.log_level,
        )
