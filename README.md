# Ocickle Auth Python SDK

A small, dependency-light Python client for the Ocickle Auth API
(`https://api.auth.ocickle.com`). Covers registration, login, email
verification, account management, and session management

## Install

```bash
pip install -e .
```

## Usage

```python
from ocickle_auth_python import OcickleAuthClient, Config
from ocickle_auth_python.exceptions import AuthenticationError

client = OcickleAuthClient(Config(base_url="https://api.auth.ocickle.com"))

# Register + activate
client.register(name="John Doe", email="john@example.com", password="Password123!")
client.verify_account(email="john@example.com", code="123456")  # logs in on success

# Or log in directly (identifier = username, phone, or email)
try:
    result = client.login(identifier="john@example.com", password="Password123!")
except AuthenticationError as exc:
    print(exc.status_code, exc.message)

# access_token is cached on the client after login/verify_account/refresh,
# so most calls don't need it passed explicitly:
profile = client.get_profile()

# refresh_token/device_id cookies are held in the client's session, so
# refresh() just works:
client.refresh()

client.logout()
```

## Notes

* All responses are unwrapped from the API's `{success, message, data}`
  envelope — methods return `data` directly.
* Errors raise `AuthenticationError` (401/403), `ValidationError`
  (400/409/422), `NotFoundError` (404), or `APIError` (other non-2xx),
  all subclasses of `OcickleError` with `.message`, `.status_code`, and
  `.errors`.
* `refresh()` relies on the session's cookie jar rather than taking a
  refresh token argument, since the API only ever hands the refresh token
  back as a `Secure, HttpOnly` cookie.
