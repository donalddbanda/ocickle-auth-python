class OcickleError(Exception):
    """Base SDK error."""


class AuthenticationError(OcickleError):
    """Raised when authentication fails (401/403)."""


class APIError(OcickleError):
    """Raised for non-2xx API responses."""


class ConnectionError(OcickleError):
    """Raised for network/connection errors."""
