"""Confidential backend authorization-code client with S256 PKCE."""
import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from .exceptions import AuthenticationError, ConnectionError


class OAuthClient:
    def __init__(self, client_id, api_key, redirect_uri,
                 issuer="https://api.auth.ocickle.com",
                 authorize_url="https://account.ocickle.com/authorize", timeout=30):
        for value in (issuer, authorize_url, redirect_uri):
            url = urlsplit(value)
            if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
                raise ValueError("OAuth endpoints and callback must use HTTPS")
        if not client_id or not api_key:
            raise ValueError("Client ID and API key are required")
        self.client_id, self.api_key, self.redirect_uri = client_id, api_key, redirect_uri
        self.issuer, self.authorize_url, self.timeout = issuer.rstrip('/'), authorize_url, timeout
        self.session = requests.Session()

    def begin(self):
        pending = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
                   "verifier": secrets.token_urlsafe(48)}
        challenge = base64.urlsafe_b64encode(hashlib.sha256(pending['verifier'].encode()).digest()).rstrip(b'=').decode()
        values = dict(client_id=self.client_id, redirect_uri=self.redirect_uri, response_type='code',
                      scope='openid profile email', state=pending['state'], nonce=pending['nonce'],
                      code_challenge=challenge, code_challenge_method='S256')
        return self.authorize_url + '?' + urlencode(values), pending

    def _request(self, method, path, **kwargs):
        headers = {'X-API-Key': self.api_key, **kwargs.pop('headers', {})}
        try:
            response = self.session.request(method, self.issuer+path, headers=headers,
                timeout=self.timeout, allow_redirects=False, **kwargs)
            data = response.json()
        except requests.RequestException as exc:
            raise ConnectionError("Ocickle Account is unavailable. Please try again.") from exc
        except ValueError as exc:
            raise AuthenticationError("Invalid response from Ocickle Account.") from exc
        if not response.ok or not isinstance(data, dict):
            raise AuthenticationError("Ocickle sign-in failed. Please start again.", status_code=response.status_code)
        return data

    def complete(self, code, state, pending, response_issuer):
        if (not isinstance(pending, dict) or not isinstance(state, str)
                or not secrets.compare_digest(state, pending.get('state', ''))
                or response_issuer != self.issuer or not isinstance(code, str) or not code):
            raise AuthenticationError("Invalid sign-in state. Please start again.")
        tokens = self._request('POST', '/v1/oauth/token', data={
            'grant_type':'authorization_code', 'client_id':self.client_id,
            'client_secret':self.api_key, 'redirect_uri':self.redirect_uri,
            'code':code, 'code_verifier':pending['verifier']})
        try:
            header = jwt.get_unverified_header(tokens['id_token'])
            if header.get('alg') != 'RS256':
                raise ValueError('Unexpected algorithm')
            jwks = self._request('GET', '/.well-known/jwks.json')
            keys = [k for k in jwks.get('keys', []) if k.get('kid') == header.get('kid') and k.get('kty') == 'RSA']
            if len(keys) != 1:
                raise ValueError('Unknown signing key')
            key = jwt.PyJWK.from_dict(keys[0]).key
            claims = jwt.decode(tokens['id_token'], key, algorithms=['RS256'],
                audience=self.client_id, issuer=self.issuer,
                options={'require':['iss','aud','sub','iat','exp','nonce']})
            if not secrets.compare_digest(claims['nonce'], pending['nonce']):
                raise ValueError('Nonce mismatch')
            profile = self.userinfo(tokens['access_token'])
            if profile.get('sub') != claims['sub'] or profile.get('email_verified') is not True:
                raise ValueError('Identity mismatch or unverified email')
        except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
            raise AuthenticationError("Could not verify Ocickle identity.") from exc
        return tokens, profile

    def userinfo(self, access_token):
        return self._request('GET', '/v1/oauth/userinfo', headers={'Authorization': 'Bearer '+access_token})

    def refresh(self, refresh_token):
        return self._request('POST', '/v1/oauth/token', data={
            'grant_type':'refresh_token', 'client_id':self.client_id,
            'client_secret':self.api_key, 'refresh_token':refresh_token})

    def revoke(self, token, all_sessions=False):
        return self._request('POST', '/v1/oauth/revoke', data={'token':token, 'all_sessions':'true' if all_sessions else 'false'})
