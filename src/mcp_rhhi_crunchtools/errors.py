"""Safe error types that can be shown to users.

This module defines exception classes that are safe to expose to MCP clients.
Internal errors should be caught and converted to UserError before propagating.
"""

SAFE_ID_MAX_LENGTH = 40
SAFE_MESSAGE_MAX_LENGTH = 200


class UserError(Exception):
    """Base class for safe errors that can be shown to users.

    The catalog API is public and unauthenticated, so there is no credential
    to scrub; messages are still length-capped so a hostile upstream body
    cannot flood the client.
    """


class ConfigurationError(UserError):
    """Error in server configuration."""


class CatalogApiError(UserError):
    """Error from the Hummingbird catalog API."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"Catalog API error {code}: {message}"[:SAFE_MESSAGE_MAX_LENGTH])


class NotFoundError(UserError):
    """Image, tag, release or CVE not found in the catalog."""

    def __init__(self, identifier: str) -> None:
        if len(identifier) > SAFE_ID_MAX_LENGTH:
            identifier = identifier[:SAFE_ID_MAX_LENGTH] + "..."
        super().__init__(f"Not found in the catalog: {identifier}")


class RateLimitError(UserError):
    """Rate limit exceeded."""

    def __init__(self, retry_after: int | None = None) -> None:
        msg = "Rate limit exceeded."
        if retry_after:
            msg += f" Retry after {retry_after} seconds."
        super().__init__(msg)


class ValidationError(UserError):
    """Input validation error."""
