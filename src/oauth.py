from typing import NamedTuple
from authlib.jose import JsonWebKey, Key
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for
from flask.sessions import SessionMixin
from urllib.parse import urlencode

import json

from .db import KV, get_db

from .atproto import (
    is_valid_did,
    is_valid_handle,
    pds_endpoint_from_doc,
    resolve_authserver_from_pds,
    fetch_authserver_meta,
    resolve_identity,
)
from .atproto.oauth import initial_token_request, send_par_auth_request
from .security import is_safe_url
from .types import OAuthAuthRequest, OAuthSession

oauth = Blueprint("oauth", __name__, url_prefix="/oauth")


@oauth.get("/start")
async def oauth_start():
    # Identity
    username = request.args.get("username") or request.args.get("authserver")
    if not username:
        return redirect(url_for("page_login"), 303)

    db = get_db(current_app)
    pdskv = KV(db, "authserver_from_pds")

    if is_valid_handle(username) or is_valid_did(username):
        login_hint = username
        kv = KV(db, "did_from_handle")
        identity = await resolve_identity(username, didkv=kv)
        if identity is None:
            return "couldnt resolve identity", 500
        did, handle, doc = identity
        pds_url = pds_endpoint_from_doc(doc)
        if not pds_url:
            return "pds not found", 404
        current_app.logger.debug(f"account PDS: {pds_url}")
        authserver_url = await resolve_authserver_from_pds(pds_url, pdskv)
        if not authserver_url:
            return "authserver not found", 404

    elif username.startswith("https://") and is_safe_url(username):
        did, handle, pds_url = None, None, None
        login_hint = None
        authserver_url = await resolve_authserver_from_pds(username, pdskv) or username

    else:
        return "not a valid handle, did or auth server", 400

    current_app.logger.debug(f"Authserver: {authserver_url}")
    assert is_safe_url(authserver_url)
    authserver_meta = await fetch_authserver_meta(authserver_url)
    if not authserver_meta:
        return "no authserver meta", 404

    # Auth
    dpop_private_jwk: Key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    scope = "atproto transition:generic"

    host = request.host
    metadata_endpoint = url_for("oauth.oauth_metadata")
    client_id = f"https://{host}{metadata_endpoint}"
    callback_endpoint = url_for("oauth.oauth_callback")
    redirect_uri = f"https://{host}{callback_endpoint}"

    current_app.logger.debug(client_id)
    current_app.logger.debug(redirect_uri)

    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])

    pkce_verifier, state, dpop_authserver_nonce, resp = await send_par_auth_request(
        authserver_url,
        authserver_meta,
        login_hint,
        client_id,
        redirect_uri,
        scope,
        CLIENT_SECRET_JWK,
        dpop_private_jwk,
    )

    if resp.status == 400:
        current_app.logger.debug("PAR request returned error 400")
        current_app.logger.debug(resp.text)
        return redirect(url_for("page_login"), 303)
    _ = resp.raise_for_status()

    respjson: dict[str, str] = await resp.json()
    par_request_uri: str = respjson["request_uri"]
    current_app.logger.debug(f"saving oauth_auth_request to DB  state={state}")

    oauth_request = OAuthAuthRequest(
        state,
        authserver_meta["issuer"],
        did,
        handle,
        pds_url,
        pkce_verifier,
        scope,
        dpop_authserver_nonce,
        dpop_private_jwk.as_json(is_private=True),
    )
    save_auth_request(session, oauth_request)

    auth_endpoint = authserver_meta["authorization_endpoint"]
    assert is_safe_url(auth_endpoint)
    qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
    return redirect(f"{auth_endpoint}?{qparam}")


@oauth.get("/callback")
async def oauth_callback():
    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]

    auth_request = get_auth_request(session)
    if not auth_request:
        return redirect(url_for("page_login"), 303)

    current_app.logger.debug(f"Deleting auth request for state={state}")
    delete_auth_request(session)

    assert auth_request.authserver_iss == authserver_iss
    assert auth_request.state == state

    app_url = request.url_root.replace("http://", "https://")
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    tokens, dpop_authserver_nonce = await initial_token_request(
        auth_request,
        authorization_code,
        app_url,
        CLIENT_SECRET_JWK,
    )

    row = auth_request

    db = get_db(current_app)
    didkv = KV(db, "did_from_handle")
    authserverkv = KV(db, "authserver_from_pds")

    if row.did:
        # If we started with an account identifier, this is simple
        did, handle, pds_url = row.did, row.handle, row.pds_url
        assert tokens.sub == did
    else:
        did = tokens.sub
        assert is_valid_did(did)
        identity = await resolve_identity(did, didkv=didkv)
        if not identity:
            return "could not resolve identity", 500
        did, handle, did_doc = identity
        pds_url = pds_endpoint_from_doc(did_doc)
        if not pds_url:
            return "could not resolve pds", 500
        authserver_url = await resolve_authserver_from_pds(pds_url, authserverkv)
        assert authserver_url == authserver_iss

    assert row.scope == tokens.scope
    assert pds_url is not None

    current_app.logger.debug("storing user oauth session")
    oauth_session = OAuthSession(
        did,
        handle,
        pds_url,
        authserver_iss,
        tokens.access_token,
        tokens.refresh_token,
        dpop_authserver_nonce,
        None,
        auth_request.dpop_private_jwk,
    )
    save_auth_session(session, oauth_session)

    return redirect(url_for("page_login"))


@oauth.get("/metadata")
def oauth_metadata():
    host = request.host
    callback_endpoint = url_for("oauth.oauth_callback")
    metadata_endpoint = url_for("oauth.oauth_metadata")
    jwks_endpoint = url_for("oauth.oauth_jwks")
    return jsonify(
        {
            "client_id": f"https://{host}{metadata_endpoint}",
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "atproto transition:generic",
            "response_types": ["code"],
            "redirect_uris": [
                f"https://{host}{callback_endpoint}",
            ],
            "dpop_bound_access_tokens": True,
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks_uri": f"https://{host}{jwks_endpoint}",
            # optional
            "client_name": "ligo.at",
            "client_uri": f"https://{host}",
            "logo_uri": f"https://{host}{url_for('static', filename='favicon-48.png')}",
            "tos_uri": f"https://{host}{url_for('page_terms')}",
        }
    )


@oauth.get("/jwks")
def oauth_jwks():
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
    return jsonify({"keys": [CLIENT_PUB_JWK]})


# Session storage


def save_auth_request(session: SessionMixin, request: OAuthAuthRequest):
    return _set_into_session(session, "oauth_auth_request", request)


def save_auth_session(session: SessionMixin, auth_session: OAuthSession):
    return _set_into_session(session, "oauth_auth_session", auth_session)


def delete_auth_request(session: SessionMixin):
    return _delete_from_session(session, "oauth_auth_request")


def delete_auth_session(session: SessionMixin):
    return _delete_from_session(session, "oauth_auth_session")


def get_auth_request(session: SessionMixin) -> OAuthAuthRequest | None:
    try:
        return OAuthAuthRequest(**session["oauth_auth_request"])
    except (KeyError, TypeError) as exception:
        current_app.logger.debug("unable to load oauth_auth_request")
        current_app.logger.debug(exception)
        return None


def get_auth_session(session: SessionMixin) -> OAuthSession | None:
    try:
        return OAuthSession(**session["oauth_auth_session"])
    except (KeyError, TypeError) as exception:
        current_app.logger.debug("unable to load oauth_auth_session")
        current_app.logger.debug(exception)
        return None


def _set_into_session(session: SessionMixin, key: str, value: NamedTuple):
    session[key] = value._asdict()


def _delete_from_session(session: SessionMixin, key: str):
    del session[key]
