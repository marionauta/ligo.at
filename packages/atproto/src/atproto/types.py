from datetime import datetime, timezone
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
    expires_at: int | None
    dpop_authserver_nonce: str
    dpop_pds_nonce: str | None
    dpop_private_jwk: str

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return True

        if now is None:
            now = datetime.now(timezone.utc)

        return self.expires_at < int(now.timestamp())
