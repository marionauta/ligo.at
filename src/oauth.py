import json
from urllib.parse import urlencode

from aiohttp.client import ClientSession
from authlib.jose import JsonWebKey, Key
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for

from src.atproto import (
    fetch_authserver_meta,
    is_valid_did,
    is_valid_handle,
    pds_endpoint_from_doc,
    resolve_authserver_from_pds,
    resolve_identity,
)
from src.atproto.oauth import initial_token_request, send_par_auth_request
from src.atproto.types import OAuthAuthRequest, OAuthSession
from src.auth import (
    delete_auth_request,
    get_auth_request,
    save_auth_request,
    save_auth_session,
)
from src.db import KV, get_db
from src.security import is_safe_url

oauth = Blueprint("oauth", __name__, url_prefix="/oauth")


@oauth.get("/start")
async def oauth_start():
    # Identity
    username = request.args.get("username_or_authserver")
    if not username:
        return redirect(url_for("page_login"), 303)

    db = get_db(current_app)
    pdskv = KV(db, current_app.logger, "authserver_from_pds")

    client = ClientSession()

    if is_valid_handle(username) or is_valid_did(username):
        login_hint = username
        kv = KV(db, current_app.logger, "did_from_handle")
        identity = await resolve_identity(client, username, didkv=kv)
        if identity is None:
            return "couldnt resolve identity", 500
        did, handle, doc = identity
        pds_url = pds_endpoint_from_doc(doc)
        if not pds_url:
            return "pds not found", 404
        current_app.logger.debug(f"account PDS: {pds_url}")
        authserver_url = await resolve_authserver_from_pds(client, pds_url, pdskv)
        if not authserver_url:
            return "authserver not found", 404

    elif username.startswith("https://") and is_safe_url(username):
        did, handle, pds_url = None, None, None
        login_hint = None
        authserver_url = (
            await resolve_authserver_from_pds(client, username, pdskv) or username
        )

    else:
        return "not a valid handle, did or auth server", 400

    current_app.logger.debug(f"Authserver: {authserver_url}")
    assert is_safe_url(authserver_url)
    authserver_meta = await fetch_authserver_meta(client, authserver_url)
    if not authserver_meta:
        return "no authserver meta", 404

    await client.close()

    # Auth
    dpop_private_jwk: Key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    scope = "atproto transition:generic"

    host = request.host
    metadata_endpoint = url_for("oauth.oauth_metadata")
    client_id = f"https://{host}{metadata_endpoint}"
    callback_endpoint = url_for("oauth.oauth_callback")
    redirect_uri = f"https://{host}{callback_endpoint}"

    current_app.logger.debug(f"client_id {client_id}")
    current_app.logger.debug(f"redirect_uri {redirect_uri}")

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
        current_app.logger.warning("PAR request returned error 400")
        current_app.logger.warning(await resp.text())
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
    if "code" not in request.args:
        message = f"{request.args['error']}: {request.args['error_description']}"
        current_app.logger.debug(message)
        return redirect(url_for("page_login"))
    authorization_code = request.args["code"]

    auth_request = get_auth_request(session)
    if not auth_request:
        return redirect(url_for("page_login"), 303)

    current_app.logger.debug(f"Deleting auth request for state={state}")
    delete_auth_request(session)

    assert auth_request.authserver_iss == authserver_iss
    assert auth_request.state == state

    client = ClientSession()

    app_url = request.url_root.replace("http://", "https://")
    CLIENT_SECRET_JWK = JsonWebKey.import_key(current_app.config["CLIENT_SECRET_JWK"])
    tokens, dpop_authserver_nonce = await initial_token_request(
        client,
        auth_request,
        authorization_code,
        app_url,
        CLIENT_SECRET_JWK,
    )

    row = auth_request

    db = get_db(current_app)
    didkv = KV(db, current_app.logger, "did_from_handle")
    authserverkv = KV(db, current_app.logger, "authserver_from_pds")

    if row.did:
        # If we started with an account identifier, this is simple
        did, handle, pds_url = row.did, row.handle, row.pds_url
        assert tokens.sub == did
    else:
        did = tokens.sub
        assert is_valid_did(did)
        identity = await resolve_identity(client, did, didkv=didkv)
        if not identity:
            return "could not resolve identity", 500
        did, handle, did_doc = identity
        pds_url = pds_endpoint_from_doc(did_doc)
        if not pds_url:
            return "could not resolve pds", 500
        authserver_url = await resolve_authserver_from_pds(
            client,
            pds_url,
            authserverkv,
        )
        assert authserver_url == authserver_iss

    await client.close()

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
