import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from ocickle_auth_python import Config, OcickleAuthClient
from ocickle_auth_python.oauth import OAuthClient
from ocickle_auth_python.exceptions import AuthenticationError


class OAuthTests(unittest.TestCase):
    def test_client_key_and_user_bearer_coexist(self):
        client = OcickleAuthClient(Config(api_key='client-secret'))
        request = __import__('requests').Request('GET', client._url('/v1/account/me'), headers=client._auth_headers('user-token'))
        prepared = client._session.prepare_request(request)
        self.assertEqual(prepared.headers['X-API-Key'], 'client-secret')
        self.assertEqual(prepared.headers['Authorization'], 'Bearer user-token')
        self.assertEqual(client._url('/v1/auth/login').count('/v1'), 1)
        self.assertEqual(OcickleAuthClient(Config(base_url='https://api.auth.ocickle.com/v1'))._url('/.well-known/jwks.json'), 'https://api.auth.ocickle.com/.well-known/jwks.json')


    def test_pkce_state_and_nonce_are_random(self):
        client = OAuthClient('id', 'secret', 'https://app.example/callback')
        url, first = client.begin()
        _, second = client.begin()
        self.assertNotEqual(first, second)
        self.assertEqual(parse_qs(urlsplit(url).query)['code_challenge_method'], ['S256'])
        self.assertNotIn(first['verifier'], url)
        self.assertNotIn('secret', url)


    def test_bad_callback_rejected_before_network(self):
        client = OAuthClient('id', 'secret', 'https://app.example/callback')
        _, pending = client.begin()
        args = dict(code='code', state=pending['state'], pending=pending, response_issuer=client.issuer)
        for change in ({'state': 'wrong'}, {'response_issuer': 'https://evil.example'}, {'code': None}):
            with self.subTest(change=change), patch.object(client.session, 'request') as request:
                with self.assertRaises(AuthenticationError):
                    client.complete(**{**args, **change})
                request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
