from atproto import Client
from atproto.exceptions import AtProtocolError
from atproto_client.models import ComAtprotoRepoCreateRecord
from atproto_client.models.app.bsky.actor.defs import ProfileViewDetailed
from flask import Flask, make_response, redirect, render_template, request
from urllib import request as http_request
import json

app = Flask(__name__)
pdss: dict[str, str] = {}
dids: dict[str, str] = {}
links: dict[str, list[dict[str, str]]] = {}
profiles: dict[str, tuple[str, str]] = {}

PLC_DIRECTORY = "https://plc.directory"
SCHEMA = "one.nauta"


@app.get("/")
def page_home():
    return render_template("index.html")


@app.get("/@<string:handle>")
def page_profile(handle: str):
    reload = request.args.get("reload") is not None

    did = resolve_did_from_handle(handle, reload=reload)
    if did is None:
        return "did not found", 404
    pds = resolve_pds_from_did(did, reload=reload)
    if pds is None:
        return "pds not found", 404
    profile, _ = load_profile(pds, did, reload=reload)
    links = load_links(pds, did, reload=reload)
    if links is None:
        return "profile not found", 404

    if reload:
        # remove the ?reload parameter
        return redirect(request.path)

    return render_template("profile.html", profile=profile, links=links)


@app.get("/login")
def page_login():
    if "session" in request.cookies:
        return redirect("/editor")
    return render_template("login.html")


@app.get("/editor")
def page_editor():
    session = request.cookies.get("session")
    if session is None or not session:
        return redirect("/login")
    client = Client()
    profile: ProfileViewDetailed | None
    try:
        profile = client.login(session_string=session)
    except AtProtocolError:
        r = make_response(redirect("/login", 303))
        r.delete_cookie("session")
        return r

    pds = resolve_pds_from_did(profile.did)
    if not pds:
        return "did not found", 404
    pro, from_bluesky = load_profile(pds, profile.did, reload=True)  # DONT COMMIT
    links = load_links(pds, profile.did, reload=True) or [{}]  # DONT COMMIT

    return render_template(
        "editor.html",
        handle=profile.handle,
        profile=pro,
        profile_from_bluesky=from_bluesky,
        links=json.dumps(links),
    )


@app.post("/editor/profile")
def post_editor_profile():
    session = request.cookies.get("session")
    if session is None or not session:
        return redirect("/login", 303)
    client = Client()
    profile = client.login(session_string=session)

    display_name = request.form.get("displayName")
    description = request.form.get("description") or ""
    if not display_name:
        return redirect("/editor", 303)

    put_record(
        client=client,
        repo=profile.did,
        collection=f"{SCHEMA}.actor.profile",
        rkey="self",
        record={
            "$type": f"{SCHEMA}.actor.profile",
            "displayName": display_name,
            "description": description,
        },
    )

    return redirect("/editor", 303)


@app.post("/editor/links")
def post_editor_links():
    session = request.cookies.get("session")
    if session is None or not session:
        return redirect("/login", 303)
    client = Client()
    profile = client.login(session_string=session)

    links: list[dict[str, str]] = []
    for i in range(0, 100):
        url = request.form.get(f"link{i}-url")
        title = request.form.get(f"link{i}-title")
        detail = request.form.get(f"link{i}-detail")
        color = request.form.get(f"link{i}-color")
        if not url or not title or not color:
            break
        link: dict[str, str] = {
            "url": url,
            "title": title,
            "color": color,
        }
        if detail:
            link["detail"] = detail
        links.append(link)

    app.logger.warning(links)

    put_record(
        client=client,
        repo=profile.did,
        collection=f"{SCHEMA}.actor.links",
        rkey="self",
        record={
            "$type": f"{SCHEMA}.actor.links",
            "links": links,
        },
    )

    return redirect("/editor", 303)


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


def load_profile(
    pds: str, did: str, reload: bool = False
) -> tuple[tuple[str, str] | None, bool]:
    if did in profiles and not reload:
        app.logger.debug(f"returning cached profile for {did}")
        return profiles[did], False

    from_bluesky = False
    response = get_record(pds, did, f"{SCHEMA}.actor.profile", "self")
    if response is None:
        response = get_record(pds, did, "app.bsky.actor.profile", "self")
        from_bluesky = True
    if response is None:
        return None, False

    record = json.loads(response)
    value: dict[str, str] = record["value"]
    profile = (value["displayName"], value["description"])
    app.logger.debug(f"caching profile for {did}")
    profiles[did] = profile
    return profile, from_bluesky


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


def put_record(client: Client, repo: str, collection: str, rkey: str, record):
    data_model = ComAtprotoRepoCreateRecord.Data(
        collection=collection,
        repo=repo,
        rkey=rkey,
        record=record,
    )
    _ = client.invoke_procedure(
        "com.atproto.repo.putRecord",
        data=data_model,
        input_encoding="application/json",
    )


def http_get(url: str) -> str | None:
    try:
        return http_request.urlopen(url).read()
    except http_request.HTTPError:
        return None


# AUTH


@app.route("/auth/logout")
def auth_logout():
    r = make_response(redirect("/"))
    r.delete_cookie("session")
    return r


@app.post("/auth/login")
def auth_login():
    handle = request.form.get("handle")
    password = request.form.get("password")
    if not handle or not password:
        return redirect("/login", 303)
    if handle.startswith("@"):
        handle = handle[1:]
    session_string: str | None
    try:
        client = Client()
        _ = client.login(handle, password)
        session_string = client.export_session_string()
    except AtProtocolError:
        return redirect("/login", 303)
    r = make_response(redirect("/editor", code=303))
    r.set_cookie("session", session_string)
    return r
