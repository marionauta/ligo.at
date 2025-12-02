from os import getenv
from re import match as regex_match
from typing import Any

from aiodns import DNSResolver
from aiodns import error as dns_error
from aiohttp.client import ClientResponse, ClientSession

from src.security import is_safe_url

from .kv import KV, nokv
from .validator import is_valid_authserver_meta

PLC_DIRECTORY = getenv("PLC_DIRECTORY_URL") or "https://plc.directory"
HANDLE_REGEX = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
DID_REGEX = r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$"


type AuthserverUrl = str
type PdsUrl = str
type DID = str


def is_valid_handle(handle: str) -> bool:
    return regex_match(HANDLE_REGEX, handle) is not None


def is_valid_did(did: str) -> bool:
    return regex_match(DID_REGEX, did) is not None


async def resolve_identity(
    client: ClientSession,
    query: str,
    didkv: KV = nokv,
) -> tuple[str, str, dict[str, Any]] | None:
    """Resolves an identity to a DID, handle and DID document, verifies handles bi directionally."""

    if is_valid_handle(query):
        handle = query.lower()
        did = await resolve_did_from_handle(client, handle, didkv)
        if not did:
            return None
        doc = await resolve_doc_from_did(client, did)
        if not doc:
            return None
        doc_handle = handle_from_doc(doc)
        if not doc_handle or doc_handle != handle:
            return None
        return (did, handle, doc)

    if is_valid_did(query):
        did = query
        doc = await resolve_doc_from_did(client, did)
        if not doc:
            return None
        handle = handle_from_doc(doc)
        if not handle:
            return None
        if await resolve_did_from_handle(client, handle, didkv) != did:
            return None
        return (did, handle, doc)

    return None


def handle_from_doc(doc: dict[str, list[str]]) -> str | None:
    """Return all possible handles inside the DID document."""

    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            handle = aka[5:].lower()
            if is_valid_handle(handle):
                return handle
    return None


async def resolve_did_from_handle(
    client: ClientSession,
    handle: str,
    kv: KV = nokv,
    reload: bool = False,
) -> str | None:
    """Returns the DID for a given handle."""

    if not is_valid_handle(handle):
        return None

    did = kv.get(handle)
    if did is not None and not reload:
        return did

    did = await _resolve_did_from_handle_dns(handle)
    if did is None:
        did = await _resolve_did_from_handle_wk(client, handle)

    if did is not None and is_valid_did(did):
        kv.set(handle, value=did)
        return did

    return None


async def _resolve_did_from_handle_wk(client: ClientSession, handle: str) -> str | None:
    """Resolve the DID for a given handle via .well-known"""

    url = f"https://{handle}/.well-known/atproto-did"
    response = await client.get(url)
    if response.ok:
        return await response.text()
    return None


async def _resolve_did_from_handle_dns(handle: str) -> str | None:
    """Resolve the DID for a given handle via DNS."""

    async with DNSResolver() as resolver:
        try:
            result = await resolver.query(f"_atproto.{handle}", "TXT")
        except dns_error.DNSError:
            return None

    for record in result:
        value = str(record.text).strip('"')
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


async def resolve_pds_from_did(
    client: ClientSession,
    did: DID,
    kv: KV = nokv,
    reload: bool = False,
) -> PdsUrl | None:
    pds = kv.get(did)
    if pds is not None and not reload:
        return pds

    doc = await resolve_doc_from_did(client, did)
    if doc is None:
        return None
    pds = doc["service"][0]["serviceEndpoint"]
    if pds is None:
        return None
    kv.set(did, value=pds)
    return pds


async def resolve_doc_from_did(
    client: ClientSession,
    did: DID,
) -> dict[str, Any] | None:
    """Returns the DID document"""

    response: ClientResponse | None = None

    if did.startswith("did:plc:"):
        response = await client.get(f"{PLC_DIRECTORY}/{did}")
    elif did.startswith("did:web:"):
        domain = did.split(":")[-1]
        assert is_valid_handle(domain)
        response = await client.get(f"https://{domain}/.well-known/did.json")

    if response and response.ok:
        return await response.json()
    return None


async def resolve_authserver_from_pds(
    client: ClientSession,
    pds_url: PdsUrl,
    kv: KV = nokv,
    reload: bool = False,
) -> AuthserverUrl | None:
    """Returns the authserver URL for the PDS."""

    authserver_url = kv.get(pds_url)
    if authserver_url is not None and not reload:
        return authserver_url

    assert is_safe_url(pds_url)
    endpoint = f"{pds_url}/.well-known/oauth-protected-resource"
    response = await client.get(endpoint)
    if response.status != 200:
        return None
    parsed: dict[str, list[str]] = await response.json()
    authserver_url = parsed["authorization_servers"][0]
    kv.set(pds_url, value=authserver_url)
    return authserver_url


async def fetch_authserver_meta(
    client: ClientSession,
    authserver_url: str,
) -> dict[str, str] | None:
    """Returns metadata from the authserver"""

    assert is_safe_url(authserver_url)
    endpoint = f"{authserver_url}/.well-known/oauth-authorization-server"
    response = await client.get(endpoint)
    if not response.ok:
        return None
    meta: dict[str, Any] = await response.json()
    assert is_valid_authserver_meta(meta, authserver_url)
    return meta


async def get_record(
    client: ClientSession,
    pds: str,
    repo: str,
    collection: str,
    record: str,
    type: str | None = None,
) -> dict[str, Any] | None:
    """Retrieve record from PDS. Verifies type is the same as collection name."""

    params = {"repo": repo, "collection": collection, "rkey": record}
    response = await client.get(f"{pds}/xrpc/com.atproto.repo.getRecord", params=params)
    if not response.ok:
        return None
    parsed = await response.json()
    value: dict[str, Any] = parsed["value"]
    if value["$type"] != (type or collection):
        return None
    del value["$type"]

    return value
