"""Optional Flask helpers; no frontend secrets or tokens in redirect URLs."""
from flask import current_app, request, redirect
from itsdangerous import URLSafeTimedSerializer, BadSignature
from .oauth import OAuthClient
from .exceptions import AuthenticationError

COOKIE = 'ocickle_signin'


def enabled():
    config = current_app.config
    return (config.get('OCICKLE_OAUTH_ENABLED') is True and
            all(config.get(k) for k in ('OCICKLE_CLIENT_ID','OCICKLE_AUTH_API_KEY','OCICKLE_REDIRECT_URI','SECRET_KEY')))


def client():
    if not enabled():
        raise AuthenticationError('Ocickle hosted sign-in is not configured.', status_code=503)
    c = current_app.config
    return OAuthClient(c['OCICKLE_CLIENT_ID'], c['OCICKLE_AUTH_API_KEY'], c['OCICKLE_REDIRECT_URI'],
        issuer=c.get('OCICKLE_AUTH_BASE_URL', 'https://api.auth.ocickle.com').rstrip('/'),
        authorize_url=c.get('OCICKLE_AUTHORIZE_URL', 'https://account.ocickle.com/authorize'))


def serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='ocickle-oauth-v1')


def start():
    url, pending = client().begin()
    response = redirect(url, code=302)
    response.set_cookie(COOKIE, serializer().dumps(pending), max_age=600,
        secure=True, httponly=True, samesite='Lax', path='/')
    response.headers['Cache-Control'] = 'no-store'
    return response


def complete():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise AuthenticationError('Invalid sign-in response.', status_code=400)
    try:
        pending = serializer().loads(request.cookies.get(COOKIE, ''), max_age=600)
    except BadSignature as exc:
        raise AuthenticationError('Sign-in expired. Please start again.', status_code=400) from exc
    return client().complete(body.get('code'), body.get('state'), pending, body.get('iss'))


def clear_pending(response):
    response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='Lax')
    response.headers['Cache-Control'] = 'no-store'
    return response


def profile_for_product(profile):
    return {**profile, 'id': int(profile['sub']), 'username': profile.get('preferred_username'),
            'is_active': profile.get('email_verified') is True}
