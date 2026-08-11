"""HTTP client for the Ocickle Auth API (https://api.auth.ocickle.com).

Endpoints and payload shapes follow docs/api_reference.md and
docs/authentication_flow.md in the ocickle-account repo.
"""
from typing import Any, Dict, Optional

import requests

from .config import Config
from .exceptions import (
    APIError,
    AuthenticationError,
    ConnectionError,
    NotFoundError,
    ValidationError,
)


class OcickleAuthClient:
    """Client for the Ocickle Auth API.

    Two things the raw API does that this client handles for you:

    * Every response is wrapped as ``{"success": ..., "message": ...,
      "data": ...}``. Methods below return the unwrapped ``data`` payload
      on success and raise an exception (with ``.message`` /
      ``.status_code`` / ``.errors``) on failure.
    * The refresh token is a ``Secure, HttpOnly`` cookie, not a value you
      pass around. This client uses a ``requests.Session``, so the
      ``refresh_token`` and ``device_id`` cookies set by login()/
      verify_account() are kept automatically and reused by refresh() and
      logout().

    The access token returned by login()/verify_account()/refresh() is also
    cached on the client, so you don't have to thread it through every call
    unless you want to (e.g. because you're juggling multiple users).
    """

    def __init__(self, config: Optional[Config] = None):
        self._config = config or Config()
        self._session = requests.Session()
        self._access_token: Optional[str] = None
        if self._config.api_key:
            self._session.headers.update({"Authorization": f"Bearer {self._config.api_key}"})

    @property
    def access_token(self) -> Optional[str]:
        return self._access_token

    def _url(self, path: str) -> str:
        return f"{self._config.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _auth_headers(self, access_token: Optional[str]) -> Dict[str, str]:
        token = access_token or self._access_token
        if not token:
            raise AuthenticationError(
                "No access token available. Call login() or verify_account() first, "
                "or pass access_token explicitly."
            )
        return {"Authorization": f"Bearer {token}"}

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        auth: bool = False,
        access_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = self._url(path)
        headers = self._auth_headers(access_token) if auth else None

        try:
            resp = self._session.request(
                method, url, json=json, headers=headers, timeout=self._config.timeout
            )
        except requests.RequestException as exc:
            raise ConnectionError(str(exc)) from exc

        try:
            body = resp.json()
        except ValueError:
            body = None

        if 200 <= resp.status_code < 300:
            if isinstance(body, dict) and "success" in body:
                return body.get("data") or {}
            # Unenveloped endpoints (jwks, health) - return the body as-is.
            return body if isinstance(body, dict) else {"text": resp.text}

        message = (body or {}).get("message", resp.text or f"HTTP {resp.status_code}")
        errors = (body or {}).get("errors")

        if resp.status_code in (401, 403):
            raise AuthenticationError(message, status_code=resp.status_code, errors=errors)
        if resp.status_code == 404:
            raise NotFoundError(message, status_code=resp.status_code, errors=errors)
        if resp.status_code in (400, 409, 422):
            raise ValidationError(message, status_code=resp.status_code, errors=errors)
        raise APIError(message, status_code=resp.status_code, errors=errors)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def register(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """POST /v1/auth/register

        Creates an inactive account and emails a 6-digit OTP. Call
        verify_account() with the code to activate it and log in.
        """
        return self._request(
            "POST", "/v1/auth/register", json={"name": name, "email": email, "password": password}
        )

    def login(self, identifier: str, password: str) -> Dict[str, Any]:
        """POST /v1/auth/login

        `identifier` is a username, phone number, or email. Caches the
        returned access token and keeps the refresh_token/device_id cookies
        in the session for refresh()/logout().
        """
        data = self._request(
            "POST", "/v1/auth/login", json={"identifier": identifier, "password": password}
        )
        self._access_token = data.get("access_token")
        return data

    def refresh(self) -> Dict[str, Any]:
        """POST /v1/auth/refresh

        Uses the refresh_token cookie already held by the session (set
        during login/verify_account) to rotate it and mint a new access
        token, which is cached on the client.
        """
        data = self._request("POST", "/v1/auth/refresh")
        self._access_token = data.get("access_token")
        return data

    def logout(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/auth/logout — revokes the current session."""
        data = self._request("POST", "/v1/auth/logout", auth=True, access_token=access_token)
        self._access_token = None
        return data

    def logout_all(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/auth/logout-all — revokes every session for the user."""
        data = self._request("POST", "/v1/auth/logout-all", auth=True, access_token=access_token)
        self._access_token = None
        return data

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def send_verification(self, email: str) -> Dict[str, Any]:
        """POST /v1/verification/send — resend the registration OTP."""
        return self._request("POST", "/v1/verification/send", json={"email": email})

    def verify_account(self, email: str, code: str) -> Dict[str, Any]:
        """POST /v1/verification/verify

        Activates the account and logs it in. Caches the returned access
        token, same as login().
        """
        data = self._request("POST", "/v1/verification/verify", json={"email": email, "code": code})
        self._access_token = data.get("access_token")
        return data

    # ------------------------------------------------------------------
    # Account (all require auth)
    # ------------------------------------------------------------------

    def get_profile(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """GET /v1/account/me"""
        return self._request("GET", "/v1/account/me", auth=True, access_token=access_token)

    def set_username(self, username: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        """PUT /v1/account/username — can only be set once."""
        return self._request(
            "PUT", "/v1/account/username", json={"username": username}, auth=True, access_token=access_token
        )

    def update_password(
        self, current_password: str, new_password: str, access_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """PUT /v1/account/password"""
        return self._request(
            "PUT",
            "/v1/account/password",
            json={"current_password": current_password, "new_password": new_password},
            auth=True,
            access_token=access_token,
        )

    def request_email_change(self, email: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/account/email/request — sends a code to the new address."""
        return self._request(
            "POST", "/v1/account/email/request", json={"email": email}, auth=True, access_token=access_token
        )

    def verify_email_change(self, code: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/account/email/verify"""
        return self._request(
            "POST", "/v1/account/email/verify", json={"code": code}, auth=True, access_token=access_token
        )

    def resend_email_change(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/account/email/resend"""
        return self._request("POST", "/v1/account/email/resend", auth=True, access_token=access_token)

    def delete_account(self, password: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        """DELETE /v1/account — permanent."""
        data = self._request(
            "DELETE",
            "/v1/account",
            json={"password": password, "confirmation": "DELETE"},
            auth=True,
            access_token=access_token,
        )
        self._access_token = None
        return data

    # ------------------------------------------------------------------
    # Sessions (require auth)
    # ------------------------------------------------------------------

    def list_sessions(self, access_token: Optional[str] = None) -> Dict[str, Any]:
        """GET /v1/sessions"""
        return self._request("GET", "/v1/sessions", auth=True, access_token=access_token)

    def revoke_session(self, session_id: int, access_token: Optional[str] = None) -> Dict[str, Any]:
        """DELETE /v1/sessions/{id}"""
        return self._request(
            "DELETE", f"/v1/sessions/{session_id}", auth=True, access_token=access_token
        )

    # ------------------------------------------------------------------
    # Public / utility
    # ------------------------------------------------------------------

    def get_jwks(self) -> Dict[str, Any]:
        """GET /.well-known/jwks.json — public keys for verifying access tokens locally."""
        return self._request("GET", "/.well-known/jwks.json")

    def health(self) -> Dict[str, Any]:
        """GET /v1/health"""
        return self._request("GET", "/v1/health")
