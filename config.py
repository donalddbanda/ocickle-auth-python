from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """Configuration for OcickleAuthClient.

    Attributes:
        base_url: Base URL for the Ocickle Auth API. Endpoint paths already
            include the ``/v1`` prefix (e.g. ``/v1/auth/login``), so this
            should point at the host only and NOT include ``/v1``.
        api_key: Optional service-to-service API key sent as a Bearer token
            on every request. Most endpoints instead expect the per-user
            access_token returned by login()/verify_account(), which the
            client tracks automatically.
        timeout: Request timeout in seconds.
    """

    base_url: str = "https://api.auth.ocickle.com"
    api_key: Optional[str] = None
    timeout: int = 30
