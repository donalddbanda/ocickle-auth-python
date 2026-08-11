from typing import Any, Optional


class OcickleError(Exception):
    """Base SDK error.

    Carries the `message` reported by the API (`data.message` in the
    `{success, message, data}` envelope) plus the HTTP status code and any
    field-level `errors` payload, when available.
    """

    def __init__(self, message: str, *, status_code: Optional[int] = None, errors: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = errors

    def __str__(self) -> str:
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(OcickleError):
    """Raised when authentication fails or is missing (401/403)."""


class ValidationError(OcickleError):
    """Raised for invalid request data (400/422)."""


class NotFoundError(OcickleError):
    """Raised when a resource is not found (404)."""


class APIError(OcickleError):
    """Raised for other non-2xx API responses."""


class ConnectionError(OcickleError):
    """Raised for network/connection errors (DNS, timeout, refused, etc.)."""
