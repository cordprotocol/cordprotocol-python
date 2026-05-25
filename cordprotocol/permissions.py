"""
Permission scope constants and validation utilities.

Scopes mirror the TypeScript @cordprotocol/sdk SCOPES constants exactly
so permission checks are compatible across SDK implementations.
"""

from __future__ import annotations

from typing import List


class SCOPES:
    """Standard permission scopes for AI agent credentials."""

    READ = "read:data"
    WRITE = "write:data"
    EXECUTE = "execute:actions"
    COMMUNICATE = "communicate:agents"
    SPEND = "spend:budget"

    @classmethod
    def all(cls) -> List[str]:
        """Return every defined scope."""
        return [cls.READ, cls.WRITE, cls.EXECUTE, cls.COMMUNICATE, cls.SPEND]


_KNOWN_SCOPES: frozenset[str] = frozenset(SCOPES.all())


def validate_scopes(permissions: List[str]) -> List[str]:
    """Validate that every permission is a recognised scope.

    Args:
        permissions: List of scope strings to validate.

    Returns:
        The original list unchanged if all scopes are valid.

    Raises:
        ValueError: If any permission is not a known scope.
    """
    unknown = [p for p in permissions if p not in _KNOWN_SCOPES]
    if unknown:
        raise ValueError(
            f"Unknown permission scope(s): {unknown}. "
            f"Valid scopes: {sorted(_KNOWN_SCOPES)}"
        )
    return permissions
