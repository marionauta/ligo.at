from flask import Flask, render_template, request
from urllib import request as http_request
import json

app = Flask(__name__)
pdss: dict[str, str] = {}
dids: dict[str, str] = {}
links: dict[str, list[dict[str, str]]] = {}
profiles: dict[str, tuple[str, str]] = {}

PLC_DIRECTORY = "https://plc.directory"
SCHEMA = "one.nauta"


@app.route("/")
def hello_world():
    return "<3"


@app.route("/<string:handle>")
def page_profile(handle: str):
    if handle == "favicon.ico":
        return "not found", 404

    reload = request.args.get("reload") is not None

    did = resolve_did_from_handle(handle, reload=reload)
    if did is None:
        return "did not found", 404
    pds = resolve_pds_from_did(did, reload=reload)
    if pds is None:
        return "pds not found", 404
    profile = load_profile(pds, did, reload=reload)
    links = load_links(pds, did, reload=reload) or []
    return render_template("profile.html", profile=profile, links=links)


def load_links(pds: str, did: str, reload: bool = False) -> list[dict[str, str]] | None:
    if did in links and not reload:
        app.logger.debug(f"returning cached links for {did}")
        return links[did]

    response = get_record(pds, did, f"{SCHEMA}.actor.links", "self")
    if response is None:
        return None

    record = json.loads(response)
    link = record["value"]["links"]
    app.logger.debug(f"caching links for {did}")
    links[did] = link
    return link


def load_profile(pds: str, did: str, reload: bool = False) -> tuple[str, str] | None:
    if did in profiles and not reload:
        app.logger.debug(f"returning cached profile for {did}")
        return profiles[did]

    response = get_record(pds, did, f"{SCHEMA}.actor.profile", "self")
    if response is None:
        response = get_record(pds, did, "app.bsky.actor.profile", "self")
    if response is None:
        return None

    record = json.loads(response)
    value: dict[str, str] = record["value"]
    profile = (value["displayName"], value["description"])
    app.logger.debug(f"caching profile for {did}")
    profiles[did] = profile
    return profile


def resolve_pds_from_did(did: str, reload: bool = False) -> str | None:
    if did in pdss and not reload:
        app.logger.debug(f"returning cached pds for {did}")
        return pdss[did]

    response = http_get(f"{PLC_DIRECTORY}/{did}")
    if response is None:
        return None
    parsed = json.loads(response)
    pds = parsed["service"][0]["serviceEndpoint"]
    pdss[did] = pds
    app.logger.debug(f"caching pds {pds} for {did}")
    return pds


def resolve_did_from_handle(handle: str, reload: bool = False) -> str | None:
    if handle in dids and not reload:
        app.logger.debug(f"returning cached did for {handle}")
        return dids[handle]

    response = http_get(f"https://dns.google/resolve?name=_atproto.{handle}&type=TXT")
    if response is None:
        return None
    parsed = json.loads(response)
    answers = parsed["Answer"]
    if len(answers) < 1:
        return handle
    data: str = answers[0]["data"]
    if not data.startswith("did="):
        return handle
    did = data[4:]
    dids[handle] = did
    app.logger.debug(f"caching did {did} for {handle}")
    return did


def get_record(pds: str, repo: str, collection: str, record: str) -> str | None:
    response = http_get(
        f"{pds}/xrpc/com.atproto.repo.getRecord?repo={repo}&collection={collection}&rkey={record}"
    )
    return response


def http_get(url: str) -> str | None:
    try:
        return http_request.urlopen(url).read()
    except http_request.HTTPError:
        return None
