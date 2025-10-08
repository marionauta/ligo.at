from authlib.jose import JsonWebKey, Key
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for
from urllib.parse import urlencode

import json

from .atproto.atproto_identity import is_valid_did, is_valid_handle
from .atproto.atproto_oauth import initial_token_request, send_par_auth_request
from .atproto.atproto_security import is_safe_url
from .atproto import (
    pds_endpoint_from_doc,
    resolve_authserver_from_pds,
    resolve_authserver_meta,
    resolve_identity,
)
from .types import OAuthAuthRequest
from .db import get_db

oauth = Blueprint("oauth", __name__, url_prefix="/oauth")


@oauth.get("/start")
def oauth_start():
    # Identity
    username = request.args.get("username")
    if not username:
        return "missing ?username", 400

    if is_valid_handle(username) or is_valid_did(username):
        login_hint = username
        identity = resolve_identity(username)
        if identity is None:
            return "couldnt resolve identity", 500
        did, handle, doc = identity
        pds_url = pds_endpoint_from_doc(doc)
        if not pds_url:
            return "pds not found", 404
        current_app.logger.debug(f"account PDS: {pds_url}")
        authserver_url = resolve_authserver_from_pds(pds_url)
        if not authserver_url:
            return "authserver not found", 404

    elif username.startswith("https://") and is_safe_url(username):
        did, handle, pds_url = None, None, None
        login_hint = None
        authserver_url = resolve_authserver_from_pds(username) or username

    else:
        return "not a valid handle, did or auth server", 400

    current_app.logger.debug(f"Authserver: {authserver_url}")
    assert is_safe_url(authserver_url)
    authserver_meta = resolve_authserver_meta(authserver_url)
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

    pkce_verifier, state, dpop_authserver_nonce, resp = send_par_auth_request(
        authserver_url,
        authserver_meta,
        login_hint,
        client_id,
        redirect_uri,
        scope,
        CLIENT_SECRET_JWK,
        dpop_private_jwk,
    )
    if resp.status_code == 400:
        current_app.logger.debug(f"PAR HTTP 400: {resp.json()}")
    resp.raise_for_status()

    par_request_uri: str = resp.json()["request_uri"]
    current_app.logger.debug(f"saving oauth_auth_request to DB  state={state}")

    db = get_db(current_app)
    cursor = db.cursor()
    _ = cursor.execute(
        "insert or replace into oauth_auth_requests values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            state,
            authserver_meta["issuer"],
            did,
            handle,
            pds_url,
            pkce_verifier,
            scope,
            dpop_authserver_nonce,
            dpop_private_jwk.as_json(is_private=True),
        ),
    )
    db.commit()
    cursor.close()

    auth_endpoint = authserver_meta["authorization_endpoint"]
    assert is_safe_url(auth_endpoint)
    qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
    return redirect(f"{auth_endpoint}?{qparam}")


@oauth.get("/callback")
def oauth_callback():
    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]

    db = get_db(current_app)
    cursor = db.cursor()

    row = cursor.execute(
        "select * from oauth_auth_requests where state = ?", (state,)
    ).fetchone()
    try:
        auth_request = OAuthAuthRequest(**row)
    except TypeError:
        return redirect(url_for("page_login"), 303)

    current_app.logger.debug(f"Deleting auth request for state={state}")
    _ = cursor.execute("delete from oauth_auth_requests where state = ?", (state,))
    db.commit()

    assert auth_request.authserver_iss == authserver_iss
    assert auth_request.state == state

    app_url = request.url_root.replace("http://", "https://")
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    tokens, dpop_authserver_nonce = initial_token_request(
        auth_request,
        authorization_code,
        app_url,
        CLIENT_SECRET_JWK,
    )

    row = auth_request

    did = auth_request.did
    if row.did:
        # If we started with an account identifier, this is simple
        did, handle, pds_url = row.did, row.handle, row.pds_url
        assert tokens["sub"] == did
    else:
        did = tokens["sub"]
        assert is_valid_did(did)
        identity = resolve_identity(did)
        if not identity:
            return "could not resolve identity", 500
        did, handle, did_doc = identity
        pds_url = pds_endpoint_from_doc(did_doc)
        if not pds_url:
            return "could not resolve pds", 500
        authserver_url = resolve_authserver_from_pds(pds_url)
        assert authserver_url == authserver_iss

    assert row.scope == tokens["scope"]

    current_app.logger.debug("storing user did and handle")
    db = get_db(current_app)
    cursor = db.cursor()
    _ = cursor.execute(
        "insert or replace into oauth_session values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            did,
            handle,
            pds_url,
            authserver_iss,
            tokens["access_token"],
            tokens["refresh_token"],
            dpop_authserver_nonce,
            None,
            auth_request.dpop_private_jwk,
        ),
    )
    db.commit()
    cursor.close()

    session["user_did"] = did
    session["user_handle"] = auth_request.handle

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
        }
    )


@oauth.get("/jwks")
def oauth_jwks():
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
    return jsonify({"keys": [CLIENT_PUB_JWK]})
