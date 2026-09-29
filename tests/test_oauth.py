from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import pytest
from ocickle_auth_python import Config, OcickleAuthClient
from ocickle_auth_python.oauth import OAuthClient
from ocickle_auth_python.exceptions import AuthenticationError


def test_client_key_and_user_bearer_coexist():
    client = OcickleAuthClient(Config(api_key='client-secret'))
    request = __import__('requests').Request('GET', client._url('/v1/account/me'), headers=client._auth_headers('user-token'))
    prepared = client._session.prepare_request(request)
    assert prepared.headers['X-API-Key'] == 'client-secret'
    assert prepared.headers['Authorization'] == 'Bearer user-token'
    assert client._url('/v1/auth/login').count('/v1') == 1
    assert OcickleAuthClient(Config(base_url='https://api.auth.ocickle.com/v1'))._url('/.well-known/jwks.json') == 'https://api.auth.ocickle.com/.well-known/jwks.json'


def test_pkce_state_and_nonce_are_random():
    client = OAuthClient('id','secret','https://app.example/callback')
    url, first = client.begin()
    _, second = client.begin()
    assert first != second
    assert parse_qs(urlsplit(url).query)['code_challenge_method'] == ['S256']
    assert first['verifier'] not in url
    assert 'secret' not in url


@pytest.mark.parametrize('change', [{'state':'wrong'}, {'response_issuer':'https://evil.example'}, {'code':None}])
def test_bad_callback_rejected_before_network(change):
    client = OAuthClient('id','secret','https://app.example/callback')
    _, pending = client.begin()
    args = dict(code='code',state=pending['state'],pending=pending,response_issuer=client.issuer)
    with patch.object(client.session,'request') as request:
        with pytest.raises(AuthenticationError): client.complete(**{**args,**change})
        request.assert_not_called()
