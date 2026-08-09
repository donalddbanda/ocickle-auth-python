from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """Configuration for OcickleAuthClient.

    Attributes:
        base_url: Base URL for the Ocickle Auth API (defaults to https://api.auth.ocickle.com/v1)
        api_key: Optional API key to include in requests (if used by the API)
        timeout: Request timeout in seconds
    """

    base_url: str = "api.auth.ocickle.com/v1"
    api_key: Optional[str] = None
    timeout: int = 30
