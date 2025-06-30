"""Command execution models for MinIO operations."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, computed_field


class AdminCommand(str, Enum):
    """MinIO Admin command categories."""

    USER = "user"
    POLICY = "policy"
    GROUP = "group"
    ACCESSKEY = "accesskey"
    ALIAS = "alias"


class CommandResult(BaseModel):
    """Result of a MinIO command execution."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
    )

    success: Annotated[
        bool, Field(description="Whether the command executed successfully")
    ]
    stdout: Annotated[str, Field(description="Standard output from the command")]
    stderr: Annotated[str, Field(description="Standard error from the command")]
    return_code: Annotated[int, Field(description="Exit code returned by the command")]
    command: Annotated[str, Field(description="The command that was executed")]

    @computed_field
    @property
    def failed(self) -> bool:
        """Check if the command failed."""
        return not self.success

    @computed_field
    @property
    def has_output(self) -> bool:
        """Check if command produced any output."""
        return bool(self.stdout.strip())

    @computed_field
    @property
    def has_error(self) -> bool:
        """Check if command produced any error output."""
        return bool(self.stderr.strip())
