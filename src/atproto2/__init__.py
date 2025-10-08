from dns.resolver import resolve as resolve_dns
from typing import Any
import requests

from .atproto_oauth import is_valid_authserver_meta
from .atproto_security import is_safe_url
from .atproto_identity import is_valid_did, is_valid_handle

PLC_DIRECTORY = "https://plc.directory"

AuthserverUrl = str
PdsUrl = str
DID = str

authservers: dict[PdsUrl, AuthserverUrl] = {}
dids: dict[str, DID] = {}
pdss: dict[DID, PdsUrl] = {}


def resolve_identity(query: str) -> tuple[str, str, dict[str, Any]] | None:
    """Resolves an identity to a DID, handle and DID document, verifies handles bi directionally."""

    if is_valid_handle(query):
        handle = query
        did = resolve_did_from_handle(handle)
        if not did:
            return None
        doc = resolve_doc_from_did(did)
        if not doc:
            return None
        handles = handles_from_doc(doc)
        if not handles or handle not in handles:
            return None
        return (did, handle, doc)

    if is_valid_did(query):
        # TODO: resolve did identity
        return None

    return None


def handles_from_doc(doc: dict[str, list[str]]) -> list[str]:
    """Return all possible handles inside the DID document."""
    handles: list[str] = []
    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            handle = aka[5:]
            if is_valid_handle(handle):
                handles.append(handle)
    return handles


def handle_from_doc(doc: dict[str, list[str]]) -> str | None:
    """Return the first handle inside the DID document."""
    handles = handles_from_doc(doc)
    try:
        return handles[0]
    except IndexError:
        return None


def resolve_did_from_handle(handle: str, reload: bool = False) -> str | None:
    """Returns the DID for a given handle"""

    if handle in dids and not reload:
        print(f"returning cached did for {handle}")
        return dids[handle]

    answer = resolve_dns(f"_atproto.{handle}", "TXT")
    for record in answer:
        value = str(record).replace('"', "")
        if value.startswith("did="):
            did = value[4:]
            if is_valid_did(did):
                return did

    return None


def pds_endpoint_from_doc(doc: dict[str, list[dict[str, str]]]) -> str | None:
    """Returns the PDS endpoint from the DID document."""

    for service in doc.get("service", []):
        if service.get("id") == "#atproto_pds":
            return service.get("serviceEndpoint")
    return None


def resolve_pds_from_did(did: DID, reload: bool = False) -> PdsUrl | None:
    if did in pdss and not reload:
        print(f"returning cached pds for {did}")
        return pdss[did]

    doc = resolve_doc_from_did(did)
    if doc is None:
        return None
    pds = doc["service"][0]["serviceEndpoint"]
    pdss[did] = pds
    print(f"caching pds {pds} for {did}")
    return pds


def resolve_doc_from_did(
    did: DID,
    directory: str = PLC_DIRECTORY,
) -> dict[str, Any] | None:
    if did.startswith("did:plc:"):
        response = requests.get(f"{directory}/{did}")
        if response.ok:
            return response.json()
        return None

    if did.startswith("did:web:"):
        # TODO: resolve did:web
        return None

    return None


def resolve_authserver_from_pds(
    pds_url: PdsUrl,
    reload: bool = False,
) -> AuthserverUrl | None:
    """Returns the authserver URL for the PDS."""

    if pds_url in authservers and not reload:
        print(f"returning cached authserver for PDS {pds_url}")
        return authservers[pds_url]

    assert is_safe_url(pds_url)
    endpoint = f"{pds_url}/.well-known/oauth-protected-resource"
    response = requests.get(endpoint)
    if response.status_code != 200:
        return None
    parsed: dict[str, list[str]] = response.json()
    authserver_url = parsed["authorization_servers"][0]
    print(f"caching authserver {authserver_url} for PDS {pds_url}")
    authservers[pds_url] = authserver_url
    return authserver_url


def resolve_authserver_meta(authserver_url: str) -> dict[str, str] | None:
    """Returns metadata from the authserver"""
    assert is_safe_url(authserver_url)
    endpoint = f"{authserver_url}/.well-known/oauth-authorization-server"
    meta = http_get_json(endpoint)
    assert is_valid_authserver_meta(meta, authserver_url)
    return meta


def http_get_json(url: str) -> Any | None:
    response = requests.get(url)
    if response.ok:
        return response.json()
    return None


def http_get(url: str) -> str | None:
    response = requests.get(url)
    if response.ok:
        return response.text
    return None
