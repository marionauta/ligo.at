import asyncio
import json

from flask import Flask, g, session, redirect, render_template, request, url_for
from typing import Any

from .atproto import (
    PdsUrl,
    get_record,
    is_valid_did,
    resolve_did_from_handle,
    resolve_pds_from_did,
)
from .atproto.oauth import pds_authed_req
from .db import KV, close_db_connection, init_db
from .oauth import get_auth_session, oauth, save_auth_session
from .types import OAuthSession

app = Flask(__name__)
_ = app.config.from_prefixed_env()
app.register_blueprint(oauth)
init_db(app)

SCHEMA = "at.ligo"


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


@app.get("/<string:atid>")
async def page_profile(atid: str):
    reload = request.args.get("reload") is not None

    if atid.startswith("@"):
        handle = atid[1:].lower()
        did = await resolve_did_from_handle(handle, reload=reload)
        if did is None:
            return render_template("error.html", message="did not found"), 404
    elif is_valid_did(atid):
        did = atid
    else:
        return render_template("error.html", message="invalid did or handle"), 400

    if _is_did_blocked(did):
        return render_template("error.html", message="profile not found"), 404

    kv = KV(app, "pds_from_did")
    pds = await resolve_pds_from_did(did, kv, reload=reload)
    if pds is None:
        return render_template("error.html", message="pds not found"), 404
    (profile, _), links = await asyncio.gather(
        load_profile(pds, did, reload=reload),
        load_links(pds, did, reload=reload),
    )
    if links is None:
        return render_template("error.html", message="profile not found"), 404

    if reload:
        # remove the ?reload parameter
        return redirect(request.path)

    athref = f"at://{did}/at.ligo.actor.links/self"
    return render_template("profile.html", profile=profile, links=links, athref=athref)


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
async def page_editor():
    user = get_user()
    if user is None:
        return redirect("/login")

    did: str = user.did
    pds: str = user.pds_url
    handle: str | None = user.handle

    (profile, from_bluesky), links = await asyncio.gather(
        load_profile(pds, did, reload=True),
        load_links(pds, did, reload=True),
    )

    return render_template(
        "editor.html",
        handle=handle,
        profile=profile,
        profile_from_bluesky=from_bluesky,
        links=json.dumps(links or []),
    )


@app.post("/editor/profile")
async def post_editor_profile():
    user = get_user()
    if user is None:
        return redirect("/login", 303)

    display_name = request.form.get("displayName")
    description = request.form.get("description") or ""
    if not display_name:
        return redirect("/editor", 303)

    await put_record(
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
async def post_editor_links():
    user = get_user()
    if user is None:
        return redirect("/login", 303)

    links: list[dict[str, str]] = []
    hrefs = request.form.getlist("link-href")
    titles = request.form.getlist("link-title")
    subtitles = request.form.getlist("link-subtitle")
    backgrounds = request.form.getlist("link-background-color")
    for href, title, subtitle, background in zip(hrefs, titles, subtitles, backgrounds):
        if not href or not title or not background:
            break
        link: dict[str, str] = {
            "href": href,
            "title": title,
            "backgroundColor": background,
        }
        if subtitle:
            link["subtitle"] = subtitle
        links.append(link)

    await put_record(
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


async def load_links(
    pds: str,
    did: str,
    reload: bool = False,
) -> list[dict[str, str]] | None:
    kv = KV(app, "links_from_did")
    recordstr = kv.get(did)

    if recordstr is not None and not reload:
        app.logger.debug(f"returning cached links for {did}")
        return json.loads(recordstr)["links"]

    record = await get_record(pds, did, f"{SCHEMA}.actor.links", "self")
    if record is None:
        return None

    app.logger.debug(f"caching links for {did}")
    kv.set(did, value=json.dumps(record))
    return record["links"]


async def load_profile(
    pds: str,
    did: str,
    fallback_with_bluesky: bool = True,
    reload: bool = False,
) -> tuple[dict[str, str] | None, bool]:
    kv = KV(app, "profile_from_did")
    recordstr = kv.get(did)

    if recordstr is not None and not reload:
        app.logger.debug(f"returning cached profile for {did}")
        return json.loads(recordstr), False

    from_bluesky = False
    record = await get_record(pds, did, f"{SCHEMA}.actor.profile", "self")
    if record is None and fallback_with_bluesky:
        record = await get_record(pds, did, "app.bsky.actor.profile", "self")
        from_bluesky = True
    if record is None:
        return None, False

    app.logger.debug(f"caching profile for {did}")
    kv.set(did, value=json.dumps(record))
    return record, from_bluesky


# TODO: move to .atproto
async def put_record(
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

    response = await pds_authed_req(
        method="POST",
        url=endpoint,
        body=body,
        user=user,
        update_dpop_pds_nonce=update_dpop_pds_nonce,
    )
    if not response or not response.ok:
        app.logger.warning("PDS HTTP ERROR")


def _is_did_blocked(did: str) -> bool:
    kv = KV(app, "blockeddids")
    return kv.get(did) is not None
