from authlib.jose import JsonWebKey, Key
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for
from urllib.parse import urlencode

import json

from .atproto2.atproto_oauth import initial_token_request, send_par_auth_request

from .atproto2.atproto_security import is_safe_url

from .atproto2 import (
    pds_endpoint_from_doc,
    resolve_authserver_from_pds,
    resolve_authserver_meta,
    resolve_identity,
)

oauth = Blueprint("oauth", __name__, url_prefix="/oauth")


oauth_auth_requests: dict[str, dict[str, str]] = {}
oauth_session: dict[str, dict[str, str]] = {}


@oauth.get("/home")
def oauth_home():
    user_did = session["user_did"]
    user_handle = session["user_handle"]
    return f"{user_did} {user_handle}"


@oauth.get("/start")
def oauth_start():
    # Identity
    username = request.args.get("username")
    if not username:
        return "missing ?username", 400
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
    current_app.logger.debug(f"Authserver: {authserver_url}")

    assert is_safe_url(authserver_url)
    authserver_meta = resolve_authserver_meta(authserver_url)
    if not authserver_meta:
        return "no authserver meta", 404

    # Auth
    dpop_private_jwk: Key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    scope = "atproto transition:generic"

    app_url = request.url_root.replace("http://", "https://")
    redirect_uri = f"{app_url}oauth/callback"
    client_id = f"{app_url}oauth/metadata"

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
        print(f"PAR HTTP 400: {resp.json()}")
    resp.raise_for_status()

    par_request_uri = resp.json()["request_uri"]
    current_app.logger.debug(f"saving oauth_auth_request to DB  state={state}")
    oauth_auth_requests[state] = {
        "authserver_iss": authserver_meta["issuer"],
        "did": did,
        "handle": handle,
        "pds_url": pds_url,
        "pkce_verifier": pkce_verifier,
        "scope": scope,
        "dpop_authserver_nonce": dpop_authserver_nonce,
        "dpop_private_jwk": dpop_private_jwk.as_json(is_private=True),
    }

    auth_url = authserver_meta["authorization_endpoint"]
    assert is_safe_url(auth_url)
    qparam = urlencode({"client_id": client_id, "request_uri": par_request_uri})
    return redirect(f"{auth_url}?{qparam}")


@oauth.get("/callback")
def oauth_callback():
    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]

    auth_request = oauth_auth_requests.get(state)
    if auth_request is None:
        return redirect(url_for("oauth.oauth_home"), 303)

    current_app.logger.debug(f"Deleting auth request for state={state}")
    _ = oauth_auth_requests.pop(state)

    assert auth_request["authserver_iss"] == authserver_iss
    # assert state ????

    app_url = request.url_root.replace("http://", "https://")
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    tokens, dpop_authserver_nonce = initial_token_request(
        auth_request,
        authorization_code,
        app_url,
        CLIENT_SECRET_JWK,
    )

    row = auth_request

    did = auth_request["did"]
    if row["did"]:
        # If we started with an account identifier, this is simple
        did, handle, pds_url = row["did"], row["handle"], row["pds_url"]
        assert tokens["sub"] == did
    else:
        # we started with auth server URL
        raise Exception()

    assert row["scope"] == tokens["scope"]

    oauth_session[did] = {
        "did": did,
        "handle": handle,
        "pds_url": pds_url,
        "authserver_iss": authserver_iss,
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "dpop_authserver_nonce": dpop_authserver_nonce,
        "dpop_private_jwk": auth_request["dpop_private_jwk"],
    }

    current_app.logger.debug("storing user did and handle")

    session["user_did"] = did
    session["user_handle"] = auth_request["handle"]

    return redirect(url_for("oauth.oauth_home"))


@oauth.get("/metadata")
def oauth_metadata():
    host = request.host
    callback_endpoint = url_for("oauth.oauth_callback")
    metadata_endpoint = url_for("oauth.oauth_metadata")
    jwks_endpoint = url_for("oauth.oauth_jwks")
    return jsonify(
        {
            "client_id": f"https://{host}{metadata_endpoint}",
            "application_type": "web",
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
