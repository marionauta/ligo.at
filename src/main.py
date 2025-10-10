from flask import Flask, g, session, redirect, render_template, request, url_for
from typing import Any
import json

from .atproto import PdsUrl, get_record, resolve_did_from_handle, resolve_pds_from_did
from .atproto.oauth import pds_authed_req
from .db import close_db_connection, init_db
from .oauth import get_auth_session, oauth, save_auth_session
from .types import OAuthSession

app = Flask(__name__)
_ = app.config.from_prefixed_env()
app.register_blueprint(oauth)
init_db(app)

links: dict[str, list[dict[str, str]]] = {}
profiles: dict[str, tuple[str, str]] = {}

SCHEMA = "one.nauta"


@app.before_request
def load_user_to_context():
    g.user = get_auth_session(session)


def get_user() -> OAuthSession | None:
    return g.user


@app.teardown_appcontext
def app_teardown(exception: BaseException | None):
    close_db_connection(exception)


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
    if get_user() is not None:
        return redirect("/editor")
    return render_template("login.html")


@app.post("/login")
def auth_login():
    username = request.form.get("username", "")
    if username[0] == "@":
        username = username[1:]
    if not username:
        return redirect(url_for("page_login"), 303)
    return redirect(url_for("oauth.oauth_start", username=username), 303)


@app.route("/auth/logout")
def auth_logout():
    session.clear()
    return redirect("/", 303)


@app.get("/editor")
def page_editor():
    user = get_user()
    if user is None:
        return redirect("/login")

    did: str = user.did
    pds: str = user.pds_url
    handle: str | None = user.handle

    profile, from_bluesky = load_profile(pds, did, reload=True)
    links = load_links(pds, did, reload=True) or [{"background": "#fa0"}]

    return render_template(
        "editor.html",
        handle=handle,
        profile=profile,
        profile_from_bluesky=from_bluesky,
        links=json.dumps(links),
    )


@app.post("/editor/profile")
def post_editor_profile():
    user = get_user()
    if user is None:
        return redirect("/login", 303)

    display_name = request.form.get("displayName")
    description = request.form.get("description") or ""
    if not display_name:
        return redirect("/editor", 303)

    put_record(
        user=user,
        pds=user.pds_url,
        repo=user.did,
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
    user = get_user()
    if user is None:
        return redirect("/login", 303)

    links: list[dict[str, str]] = []
    urls = request.form.getlist("link-url")
    titles = request.form.getlist("link-title")
    details = request.form.getlist("link-detail")
    backgrounds = request.form.getlist("link-background")
    for url, title, detail, background in zip(urls, titles, details, backgrounds):
        if not url or not title or not background:
            break
        link: dict[str, str] = {
            "url": url,
            "title": title,
            "color": background,
            "background": background,
        }
        if detail:
            link["detail"] = detail
        links.append(link)

    put_record(
        user=user,
        pds=user.pds_url,
        repo=user.did,
        collection=f"{SCHEMA}.actor.links",
        rkey="self",
        record={
            "$type": f"{SCHEMA}.actor.links",
            "links": links,
        },
    )

    return redirect("/editor", 303)


@app.get("/terms")
def page_terms():
    return "come back soon"


def load_links(pds: str, did: str, reload: bool = False) -> list[dict[str, str]] | None:
    if did in links and not reload:
        app.logger.debug(f"returning cached links for {did}")
        return links[did]

    response = get_record(pds, did, f"{SCHEMA}.actor.links", "self")
    if response is None:
        return None

    record = json.loads(response)
    links_ = record["value"]["links"]
    app.logger.debug(f"caching links for {did}")
    links[did] = links_
    return links_


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


def put_record(
    user: OAuthSession,
    pds: PdsUrl,
    repo: str,
    collection: str,
    rkey: str,
    record: dict[str, Any],
):
    endpoint = f"{pds}/xrpc/com.atproto.repo.putRecord"
    body = {
        "repo": repo,
        "collection": collection,
        "rkey": rkey,
        "record": record,
    }

    def update_dpop_pds_nonce(nonce: str):
        session_ = user._replace(dpop_pds_nonce=nonce)
        save_auth_session(session, session_)

    response = pds_authed_req(
        method="POST",
        url=endpoint,
        body=body,
        user=user,
        update_dpop_pds_nonce=update_dpop_pds_nonce,
    )
    if not response or not response.ok:
        app.logger.warning("PDS HTTP ERROR")
