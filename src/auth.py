from flask import current_app
from flask.sessions import SessionMixin
from typing import NamedTuple, TypeVar

from .atproto.types import OAuthAuthRequest, OAuthSession


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
    del session[key]


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
