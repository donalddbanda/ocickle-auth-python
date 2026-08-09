"""Simple HTTP client for Ocickle Auth API."""
from typing import Any, Dict, Optional

import requests

from .config import Config
from .exceptions import APIError, AuthenticationError, ConnectionError


class OcickleAuthClient:
    """Client for the Ocickle Auth API.

    This is a small, dependency-light client built on requests.
    """

    def __init__(self, config: Config):
        self._config = config
        self._session = requests.Session()
        if config.api_key:
            # If the API uses a bearer API key, this is a sensible default header.
            self._session.headers.update({"Authorization": f"Bearer {config.api_key}"})

    def _url(self, path: str) -> str:
        return f"{self._config.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = self._url(path)
        try:
            resp = self._session.request(method, url, timeout=self._config.timeout, **kwargs)
        except requests.RequestException as exc:
            raise ConnectionError(str(exc)) from exc

        if 200 <= resp.status_code < 300:
            # Try parse JSON but fall back to text
            try:
                return resp.json()
            except ValueError:
                return {"text": resp.text}

        if resp.status_code in (401, 403):
            raise AuthenticationError(f"{resp.status_code} - {resp.text}")

        # Generic API error
        raise APIError(f"{resp.status_code} - {resp.text}")

    def authenticate(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate a user and return authentication tokens / session info.

        Expected API: POST /auth/login with JSON {username, password}
        """
        payload = {"email": email, "password": password}
        return self._request("POST", "/auth/login", json=payload)

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access tokens.

        Expected API: POST /auth/refresh with JSON {refresh_token}
        """
        payload = {"refresh_token": refresh_token}
        return self._request("POST", "/auth/refresh", json=payload)

    def get_profile(self, access_token: str = None) -> Dict[str, Any]:
        """Get profile for the current authenticated user.

        If access_token is provided, it will be added as a Bearer token for this call.
        Otherwise the client-wide api_key (if set) or session headers are used.
        """
        headers = None
        if access_token:
            headers = {"Authorization": f"Bearer {access_token}"}
        return self._request("GET", "/auth/me", headers=headers)

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get a user by ID. Expected API: GET /users/{user_id}
        """
        return self._request("GET", f"/users/{user_id}")

    # Add more convenience methods as required by your API surface
