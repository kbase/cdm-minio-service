# mostly copied from https://github.com/kbase/cdm-task-service/blob/main/cdmtaskservice/arg_checkers.py

import unicodedata
from typing import Any


def not_falsy(obj: Any, name: str):
    """
    Check an argument is not falsy.

    obj - the argument to check.
    name - the name of the argument to use in exceptions.

    returns the object.
    """
    if not obj:
        raise ValueError(f"{name} is required")
    return obj


def contains_control_characters(
    string: str, allowed_chars: list[str] | None = None
) -> int:
    """
    Check if a string contains control characters, as denoted by the Unicode character category
    starting with a C.
    string - the string to check.
    allowed_chars - a list of control characters that will be ignored.
    returns -1 if no characters are control characters not in allowed_chars or the position
        of the first control character found otherwise.
    """
    # See https://stackoverflow.com/questions/4324790/removing-control-characters-from-a-string-in-python  # noqa: E501
    allowed_chars = allowed_chars if allowed_chars else []
    for i, c in enumerate(string):
        if unicodedata.category(c)[0] == "C" and c not in allowed_chars:
            return i
    return -1
