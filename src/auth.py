from datetime import datetime, timedelta, timezone
from typing import NamedTuple, TypeVar

from aiohttp.client import ClientSession
from authlib.jose import JsonWebKey
from flask import current_app, request
from flask.sessions import SessionMixin

from src.atproto.oauth import refresh_token_request
from src.atproto.types import OAuthAuthRequest, OAuthSession


def save_auth_request(session: SessionMixin, request: OAuthAuthRequest):
    return _set_into_session(session, "oauth_auth_request", request)


def save_auth_session(session: SessionMixin, auth_session: OAuthSession):
    return _set_into_session(session, "oauth_auth_session", auth_session)


def delete_auth_request(session: SessionMixin):
    return _delete_from_session(session, "oauth_auth_request")


def delete_auth_session(session: SessionMixin):
    return _delete_from_session(session, "oauth_auth_session")


def get_auth_request(session: SessionMixin) -> OAuthAuthRequest | None:
    return _get_from_session(session, "oauth_auth_request", OAuthAuthRequest)


def get_auth_session(session: SessionMixin) -> OAuthSession | None:
    return _get_from_session(session, "oauth_auth_session", OAuthSession)


def _set_into_session(session: SessionMixin, key: str, value: NamedTuple):
    session[key] = value._asdict()


def _delete_from_session(session: SessionMixin, key: str):
    try:
        del session[key]
    except KeyError:
        pass


async def refresh_auth_session(
    session: SessionMixin,
    client: ClientSession,
    current: OAuthSession,
) -> OAuthSession | None:
    current_app.logger.debug("refreshing oauth tokens")
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    tokens, dpop_authserver_nonce = await refresh_token_request(
        client=client,
        user=current,
        app_host=request.host,
        client_secret_jwk=CLIENT_SECRET_JWK,
    )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=tokens.expires_in or 300)
    user = current._replace(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=int(expires_at.timestamp()),
        dpop_pds_nonce=dpop_authserver_nonce,
    )
    save_auth_session(session, user)
    return user


OAuthClass = TypeVar("OAuthClass")


def _get_from_session(
    session: SessionMixin,
    key: str,
    Type: type[OAuthClass],
) -> OAuthClass | None:
    if key not in session:
        return None

    try:
        return Type(**session[key])
    except TypeError as exception:
        current_app.logger.debug(f"unable to load {key}")
        current_app.logger.debug(exception)
        del session[key]
        return None
