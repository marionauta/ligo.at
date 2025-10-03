from flask import Flask, render_template
from urllib import request
import json

app = Flask(__name__)

PLC_DIRECTORY = "https://plc.directory"


@app.route("/")
def hello_world():
    return "<3"


@app.route("/<string:handle>")
def page_profile(handle: str):
    if handle == "favicon.ico":
        return "not found", 404

    did = resolve_did_from_handle(handle)
    pds = resolve_pds_from_did(did)
    profile = load_profile(pds, did)
    links = load_links(pds, did)
    return render_template("profile.html", profile=profile, links=links)


def load_links(pds: str, did: str) -> list[dict[str, str]]:
    response = get_record(pds, did, "one.nauta.actor.links", "self")
    record = json.loads(response)
    return record["value"]["links"]


def load_profile(pds: str, did: str) -> tuple[str, str]:
    response = get_record(pds, did, "app.bsky.actor.profile", "self")
    record = json.loads(response)
    value: dict[str, str] = record["value"]
    return (value["displayName"], value["description"])


pdss: dict[str, str] = {}


def resolve_pds_from_did(did: str, reload: bool = False) -> str:
    if did in pdss and not reload:
        app.logger.debug(f"returning cached pds for {did}")
        return pdss[did]

    response = http_get(f"{PLC_DIRECTORY}/{did}")
    parsed = json.loads(response)
    pds = parsed["service"][0]["serviceEndpoint"]
    pdss[did] = pds
    app.logger.debug(f"caching pds {pds} for {did}")
    return pds


dids: dict[str, str] = {}


def resolve_did_from_handle(handle: str, reload: bool = False) -> str:
    if handle in dids and not reload:
        app.logger.debug(f"returning cached did for {handle}")
        return dids[handle]

    response = http_get(f"https://dns.google/resolve?name=_atproto.{handle}&type=TXT")
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


def get_record(pds: str, repo: str, collection: str, record: str) -> str:
    response = http_get(
        f"{pds}/xrpc/com.atproto.repo.getRecord?repo={repo}&collection={collection}&rkey={record}"
    )
    return response


def http_get(url: str) -> str:
    return request.urlopen(url).read()
