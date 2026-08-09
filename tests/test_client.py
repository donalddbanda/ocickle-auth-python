import unittest
from unittest.mock import patch, Mock

from ocickle_auth_python import OcickleAuthClient
from ocickle_auth_python.config import Config
from ocickle_auth_python.exceptions import AuthenticationError, APIError


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("No JSON")
        return self._json


class ClientTests(unittest.TestCase):
    def setUp(self):
        cfg = Config(base_url="https://api.example")
        self.client = OcickleAuthClient(cfg)

    @patch("requests.Session.request")
    def test_authenticate_success(self, mock_request):
        mock_request.return_value = FakeResponse(200, json_data={"access_token": "abc"})
        resp = self.client.authenticate("user", "pass")
        self.assertIn("access_token", resp)
        self.assertEqual(resp["access_token"], "abc")

    @patch("requests.Session.request")
    def test_authenticate_unauthorized(self, mock_request):
        mock_request.return_value = FakeResponse(401, json_data={"error": "invalid"}, text="invalid")
        with self.assertRaises(AuthenticationError):
            self.client.authenticate("user", "wrong")

    @patch("requests.Session.request")
    def test_get_user_not_found(self, mock_request):
        mock_request.return_value = FakeResponse(404, text="not found")
        with self.assertRaises(APIError):
            self.client.get_user("does_not_exist")


if __name__ == "__main__":
    unittest.main()
