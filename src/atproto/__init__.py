import dns.resolver as dns
import httpx
from re import match as regex_match
from typing import Any

from .kv import KV, nokv
from .validator import is_valid_authserver_meta
from ..security import is_safe_url

PLC_DIRECTORY = "https://plc.directory"
HANDLE_REGEX = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
DID_REGEX = r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$"


AuthserverUrl = str
PdsUrl = str
DID = str


def is_valid_handle(handle: str) -> bool:
    return regex_match(HANDLE_REGEX, handle) is not None


def is_valid_did(did: str) -> bool:
    return regex_match(DID_REGEX, did) is not None


def resolve_identity(
    query: str,
    didkv: KV = nokv,
) -> tuple[str, str, dict[str, Any]] | None:
    """Resolves an identity to a DID, handle and DID document, verifies handles bi directionally."""

    if is_valid_handle(query):
        handle = query.lower()
        did = resolve_did_from_handle(handle, didkv)
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
        did = query
        doc = resolve_doc_from_did(did)
        if not doc:
            return None
        handle = handle_from_doc(doc)
        if not handle:
            return None
        if resolve_did_from_handle(handle, didkv) != did:
            return None
        return (did, handle, doc)

    return None


def handles_from_doc(doc: dict[str, list[str]]) -> list[str]:
    """Return all possible handles inside the DID document."""
    handles: list[str] = []
    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            handle = aka[5:].lower()
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


def resolve_did_from_handle(
    handle: str,
    kv: KV = nokv,
    reload: bool = False,
) -> str | None:
    """Returns the DID for a given handle"""

    if not is_valid_handle(handle):
        return None

    did = kv.get(handle)
    if did is not None and not reload:
        print(f"returning cached did for {handle}")
        return did

    try:
        answer = dns.resolve(f"_atproto.{handle}", "TXT")
    except dns.NXDOMAIN:
        return None

    for record in answer:
        value = str(record).replace('"', "")
        if value.startswith("did="):
            did = value[4:]
            if is_valid_did(did):
                print(f"caching did {did} for {handle}")
                kv.set(handle, value=did)
                return did

    return None


def pds_endpoint_from_doc(doc: dict[str, list[dict[str, str]]]) -> str | None:
    """Returns the PDS endpoint from the DID document."""

    for service in doc.get("service", []):
        if service.get("id") == "#atproto_pds":
            return service.get("serviceEndpoint")
    return None


def resolve_pds_from_did(
    did: DID,
    kv: KV = nokv,
    reload: bool = False,
) -> PdsUrl | None:
    pds = kv.get(did)
    if pds is not None and not reload:
        print(f"returning cached pds for {did}")
        return pds

    doc = resolve_doc_from_did(did)
    if doc is None:
        return None
    pds = doc["service"][0]["serviceEndpoint"]
    if pds is None:
        return None
    print(f"caching pds {pds} for {did}")
    kv.set(did, value=pds)
    return pds


def resolve_doc_from_did(
    did: DID,
    directory: str = PLC_DIRECTORY,
) -> dict[str, Any] | None:
    if did.startswith("did:plc:"):
        response = httpx.get(f"{directory}/{did}")
        if response.is_success:
            return response.json()
        return None

    if did.startswith("did:web:"):
        # TODO: resolve did:web
        return None

    return None


def resolve_authserver_from_pds(
    pds_url: PdsUrl,
    kv: KV = nokv,
    reload: bool = False,
) -> AuthserverUrl | None:
    """Returns the authserver URL for the PDS."""

    authserver_url = kv.get(pds_url)
    if authserver_url is not None and not reload:
        print(f"returning cached authserver for PDS {pds_url}")
        return authserver_url

    assert is_safe_url(pds_url)
    endpoint = f"{pds_url}/.well-known/oauth-protected-resource"
    response = httpx.get(endpoint)
    if response.status_code != 200:
        return None
    parsed: dict[str, list[str]] = response.json()
    authserver_url = parsed["authorization_servers"][0]
    print(f"caching authserver {authserver_url} for PDS {pds_url}")
    kv.set(pds_url, value=authserver_url)
    return authserver_url


def fetch_authserver_meta(authserver_url: str) -> dict[str, str] | None:
    """Returns metadata from the authserver"""
    assert is_safe_url(authserver_url)
    endpoint = f"{authserver_url}/.well-known/oauth-authorization-server"
    response = httpx.get(endpoint)
    if not response.is_success:
        return None
    meta: dict[str, Any] = response.json()
    assert is_valid_authserver_meta(meta, authserver_url)
    return meta


async def get_record(
    pds: str,
    repo: str,
    collection: str,
    record: str,
    type: str | None = None,
) -> dict[str, Any] | None:
    """Retrieve record from PDS. Verifies type is the same as collection name."""

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{pds}/xrpc/com.atproto.repo.getRecord?repo={repo}&collection={collection}&rkey={record}"
        )
        if not response.is_success:
            return None
        parsed = response.json()
        value: dict[str, Any] = parsed["value"]
        if value["$type"] != (type or collection):
            return None
        del value["$type"]

        return value
