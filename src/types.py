from typing import NamedTuple


class OAuthAuthRequest(NamedTuple):
    state: str
    authserver_iss: str
    did: str | None
    handle: str | None
    pds_url: str | None
    pkce_verifier: str
    scope: str
    dpop_authserver_nonce: str
    dpop_private_jwk: str


class OAuthSession(NamedTuple):
    did: str
    handle: str | None
    pds_url: str
    authserver_iss: str
    access_token: str | None
    refresh_token: str | None
    dpop_authserver_nonce: str
    dpop_pds_nonce: str | None
    dpop_private_jwk: str
