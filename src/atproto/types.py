from typing import NamedTuple, NewType

AuthserverUrl = NewType("AuthserverUrl", str)
PdsUrl = NewType("PdsUrl", str)
Handle = NewType("Handle", str)
DID = NewType("DID", str)


class OAuthAuthRequest(NamedTuple):
    state: str
    authserver_iss: str
    did: DID | None
    handle: Handle | None
    pds_url: PdsUrl | None
    pkce_verifier: str
    scope: str
    dpop_authserver_nonce: str
    dpop_private_jwk: str


class OAuthSession(NamedTuple):
    did: DID
    handle: Handle | None
    pds_url: PdsUrl
    authserver_iss: str
    access_token: str | None
    refresh_token: str | None
    dpop_authserver_nonce: str
    dpop_pds_nonce: str | None
    dpop_private_jwk: str
