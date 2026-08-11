import unittest
from unittest.mock import patch

from ocickle_auth_python import Config, OcickleAuthClient
from ocickle_auth_python.exceptions import AuthenticationError, NotFoundError, ValidationError


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.ok = 200 <= status_code < 300

    def json(self):
        if self._json is None:
            raise ValueError("No JSON")
        return self._json


def envelope(data=None, message="ok", success=True):
    return {"success": success, "message": message, "data": data or {}}


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.client = OcickleAuthClient(Config(base_url="https://api.example"))

    @patch("requests.Session.request")
    def test_login_success_caches_access_token(self, mock_request):
        mock_request.return_value = FakeResponse(
            200, json_data=envelope({"access_token": "abc", "user": {"id": 1}})
        )
        resp = self.client.login("johndoe", "pass")
        self.assertEqual(resp["access_token"], "abc")
        self.assertEqual(self.client.access_token, "abc")

        # login sends `identifier`, can either be `email`/`username`
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["json"], {"identifier": "johndoe", "password": "pass"})
        args, _ = mock_request.call_args
        self.assertEqual(args[1], "https://api.example/v1/auth/login")

    @patch("requests.Session.request")
    def test_login_unauthorized_raises_with_message(self, mock_request):
        mock_request.return_value = FakeResponse(
            401, json_data=envelope(message="Invalid credentials.", success=False)
        )
        with self.assertRaises(AuthenticationError) as ctx:
            self.client.login("johndoe", "wrong")
        self.assertEqual(ctx.exception.message, "Invalid credentials.")
        self.assertEqual(ctx.exception.status_code, 401)

    @patch("requests.Session.request")
    def test_get_profile_uses_correct_path_and_bearer_header(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data=envelope({"user": {"id": 1}}))
        self.client.get_profile(access_token="tok123")
        args, kwargs = mock_request.call_args
        self.assertEqual(args[1], "https://api.example/v1/account/me")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok123")

    @patch("requests.Session.request")
    def test_get_profile_without_token_raises(self, mock_request):
        with self.assertRaises(AuthenticationError):
            self.client.get_profile()
        mock_request.assert_not_called()

    @patch("requests.Session.request")
    def test_refresh_has_no_body_and_relies_on_session_cookies(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data=envelope({"access_token": "new-tok"}))
        resp = self.client.refresh()
        self.assertEqual(resp["access_token"], "new-tok")
        self.assertEqual(self.client.access_token, "new-tok")
        _, kwargs = mock_request.call_args
        self.assertIsNone(kwargs["json"])

    @patch("requests.Session.request")
    def test_register_conflict_maps_to_validation_error(self, mock_request):
        mock_request.return_value = FakeResponse(
            409, json_data=envelope(message="Email already in use.", success=False)
        )
        with self.assertRaises(ValidationError):
            self.client.register("John Doe", "john@example.com", "Password123!")

    @patch("requests.Session.request")
    def test_revoke_session_not_found(self, mock_request):
        mock_request.return_value = FakeResponse(404, json_data=envelope(message="Not found.", success=False))
        with self.assertRaises(NotFoundError):
            self.client.revoke_session(999, access_token="tok")

    @patch("requests.Session.request")
    def test_jwks_is_unenveloped_and_returned_as_is(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data={"keys": [{"kid": "ocickle-auth-v1"}]})
        resp = self.client.get_jwks()
        self.assertEqual(resp["keys"][0]["kid"], "ocickle-auth-v1")

    @patch("requests.Session.request")
    def test_health_is_unenveloped_and_returned_as_is(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data={"status": "ok", "version": "1.0.0"})
        resp = self.client.health()
        self.assertEqual(resp["status"], "ok")

    @patch("requests.Session.request")
    def test_logout_clears_cached_access_token(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data=envelope({}))
        self.client._access_token = "tok"
        self.client.logout()
        self.assertIsNone(self.client.access_token)


if __name__ == "__main__":
    unittest.main()
