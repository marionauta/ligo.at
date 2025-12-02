import asyncio
import json
from typing import Any, NamedTuple

from aiohttp.client import ClientSession
from flask import Flask, g, redirect, render_template, request, session, url_for
from flask_htmx import HTMX
from flask_htmx import make_response as htmx_response

from src.atproto import (
    PdsUrl,
    get_record,
    is_valid_did,
    resolve_did_from_handle,
    resolve_pds_from_did,
)
from src.atproto.oauth import pds_authed_req
from src.atproto.types import OAuthSession
from src.auth import get_auth_session, save_auth_session
from src.db import KV, close_db_connection, get_db, init_db
from src.oauth import oauth

app = Flask(__name__)
_ = app.config.from_prefixed_env()
app.register_blueprint(oauth)
htmx = HTMX()
htmx.init_app(app)
init_db(app)


@app.before_request
async def load_user_to_context():
    g.user = get_auth_session(session)


def get_user() -> OAuthSession | None:
    return g.user


@app.teardown_appcontext
async def app_teardown(exception: BaseException | None):
    close_db_connection(exception)


@app.get("/")
def page_home():
    return render_template("index.html")


@app.get("/<string:atid>")
async def page_profile(atid: str):
    reload = request.args.get("reload") is not None

    db = get_db(app)
    didkv = KV(db, app.logger, "did_from_handle")
    pdskv = KV(db, app.logger, "pds_from_did")

    async with ClientSession() as client:
        if atid.startswith("@"):
            handle = atid[1:].lower()
            did = await resolve_did_from_handle(client, handle, kv=didkv, reload=reload)
            if did is None:
                return render_template("error.html", message="did not found"), 404
        elif is_valid_did(atid):
            handle = None
            did = atid
        else:
            return render_template("error.html", message="invalid did or handle"), 400

        if _is_did_blocked(did):
            return render_template("error.html", message="profile not found"), 404

        pds = await resolve_pds_from_did(client, did=did, kv=pdskv, reload=reload)
        if pds is None:
            return render_template("error.html", message="pds not found"), 404
        (profile, _), link_sections = await asyncio.gather(
            load_profile(client, pds, did, reload=reload),
            load_links(client, pds, did, reload=reload),
        )
    if profile is None or link_sections is None:
        return render_template("error.html", message="profile not found"), 404

    if reload:
        # remove the ?reload parameter
        return redirect(request.path)

    if handle:
        profile["handle"] = handle
    athref = f"at://{did}/at.ligo.actor.links/self"
    return render_template(
        "profile.html",
        profile=profile,
        links=link_sections[0].links,
        sections=link_sections,
        athref=athref,
    )


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
    return redirect(url_for("page_login"), 303)


@app.get("/editor")
async def page_editor():
    user = get_user()
    if user is None:
        return redirect("/login", 302)

    did: str = user.did
    pds: str = user.pds_url
    handle: str | None = user.handle

    async with ClientSession() as client:
        (profile, from_bluesky), link_sections = await asyncio.gather(
            load_profile(client, pds, did),
            load_links(client, pds, did),
        )

    links = []
    if link_sections:
        links = link_sections[0].links

    return render_template(
        "editor.html",
        handle=handle,
        profile=profile,
        profile_from_bluesky=from_bluesky,
        links=json.dumps(links),
    )


@app.post("/editor/profile")
async def post_editor_profile():
    user = get_user()
    if user is None:
        url = url_for("auth_logout")
        return htmx_response(redirect=url) if htmx else redirect(url, 303)

    display_name = request.form.get("displayName")
    description = request.form.get("description", "")
    if not display_name:
        return redirect("/editor", 303)

    record = {
        "$type": "at.ligo.actor.profile",
        "displayName": display_name,
        "description": description,
    }

    success = await put_record(
        user=user,
        pds=user.pds_url,
        repo=user.did,
        collection="at.ligo.actor.profile",
        rkey="self",
        record=record,
    )

    if success:
        kv = KV(app, app.logger, "profile_from_did")
        kv.set(user.did, json.dumps(record))
    else:
        app.logger.warning("log out user for now")
        url = url_for("auth_logout")
        return htmx_response(redirect=url) if htmx else redirect(url, 303)

    if htmx:
        return htmx_response(
            render_template("_editor_profile.html", profile=record),
            reswap="outerHTML",
        )

    return redirect(url_for("page_editor"), 303)


@app.post("/editor/links")
async def post_editor_links():
    user = get_user()
    if user is None:
        url = url_for("auth_logout")
        return htmx_response(redirect=url) if htmx else redirect(url, 303)

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

    record = {
        "$type": "at.ligo.actor.links",
        "sections": [
            {
                "title": "",
                "links": links,
            }
        ],
    }

    success = await put_record(
        user=user,
        pds=user.pds_url,
        repo=user.did,
        collection="at.ligo.actor.links",
        rkey="self",
        record=record,
    )

    if success:
        kv = KV(app, app.logger, "links_from_did")
        kv.set(user.did, json.dumps(record))
    else:
        app.logger.warning("log out user for now")
        url = url_for("auth_logout")
        return htmx_response(redirect=url) if htmx else redirect(url, 303)

    if htmx:
        return htmx_response(
            render_template("_editor_links.html", links=record["sections"][0]["links"]),
            reswap="outerHTML",
        )

    return redirect(url_for("page_editor"), 303)


@app.get("/terms")
def page_terms():
    return render_template("terms.html")


class LinkSection(NamedTuple):
    title: str
    links: list[dict[str, str]]


async def load_links(
    client: ClientSession,
    pds: str,
    did: str,
    reload: bool = False,
) -> list[LinkSection] | None:
    kv = KV(app, app.logger, "links_from_did")
    record_json = kv.get(did)

    if record_json is not None and not reload:
        parsed = json.loads(record_json)
        return _links_or_sections(parsed)

    record = await get_record(client, pds, did, "at.ligo.actor.links", "self")
    if record is None:
        return None

    kv.set(did, value=json.dumps(record))
    return _links_or_sections(record)


def _links_or_sections(raw: dict[str, Any]) -> list[LinkSection] | None:
    if "sections" in raw:
        return list(map(lambda s: LinkSection(**s), raw["sections"]))
    elif "links" in raw:
        return [LinkSection("", raw["links"])]
    else:
        return None


async def load_profile(
    client: ClientSession,
    pds: str,
    did: str,
    fallback_with_bluesky: bool = True,
    reload: bool = False,
) -> tuple[dict[str, str] | None, bool]:
    kv = KV(app, app.logger, "profile_from_did")
    record_json = kv.get(did)

    if record_json is not None and not reload:
        return json.loads(record_json), False

    (record, bsky_record) = await asyncio.gather(
        get_record(client, pds, did, "at.ligo.actor.profile", "self"),
        get_record(client, pds, did, "app.bsky.actor.profile", "self"),
    )

    from_bluesky = False
    if record is None and fallback_with_bluesky:
        record = bsky_record
        from_bluesky = True

    if record is not None:
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
) -> bool:
    """Writes the record onto the users PDS. Returns bool for success."""

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

    if not response.ok:
        app.logger.warning(f"put_record failed with status {response.status}")
        app.logger.warning(await response.text())

    return response.ok


def _is_did_blocked(did: str) -> bool:
    kv = KV(app, app.logger, "blockeddids")
    return kv.get(did) is not None
