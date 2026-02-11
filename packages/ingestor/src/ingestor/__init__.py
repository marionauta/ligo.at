import asyncio
import json
import logging
import sqlite3

import dotenv
from atproto_jetstream import Jetstream, JetstreamCommitEvent, JetstreamOptions

logger = logging.getLogger(__name__)


async def ingest_jetstream(config: dict[str, str | None]):
    endpoint = "wss://jetstream1.us-east.bsky.network/subscribe"
    options = JetstreamOptions(
        endpoint=config.get("JETSTREAM_URL") or endpoint,
        wanted_collections=["at.ligo.*"],
        compress=True,
    )
    async with Jetstream(options) as stream:
        async for event in stream:
            if event.kind == "commit":
                handle_commit(event.did, event.commit, config)


def handle_commit(
    did: str,
    commit: JetstreamCommitEvent.Commit,
    config: dict[str, str | None],
):
    if commit.rkey != "self":
        return

    db = get_database(config)
    if not db:
        return
    cursor = db.cursor()

    prefix: str | None = None
    type: str | None = None
    match commit.collection:
        case "at.ligo.actor.profile":
            prefix = "profile_from_did"
            type = "at.ligo.actor.profile"
        case "at.ligo.actor.links":
            prefix = "links_from_did"
            type = "at.ligo.actor.links"
        case _:
            pass
    if prefix is None:
        return

    if isinstance(commit, JetstreamCommitEvent.DeleteCommit):
        logger.debug(f"deleting {prefix} for {did}")
        _ = cursor.execute(
            "delete from keyval where prefix = ? and key = ?",
            (prefix, did),
        )
    else:
        logger.debug(f"creating or updating {prefix} for {did}")
        if commit.record["$type"] != type:
            return
        content = json.dumps(commit.record)
        _ = cursor.execute(
            "insert or replace into keyval values (?, ?, ?)",
            (prefix, did, content),
        )

    db.commit()
    cursor.close()
    db.close()


def get_database(config: dict[str, str | None]) -> sqlite3.Connection | None:
    database_name = config.get("FLASK_DATABASE_URL") or "ligoat.db"
    return sqlite3.connect(database_name)


async def async_main(config: dict[str, str | None]):
    try:
        await ingest_jetstream(config)
    except asyncio.CancelledError:
        pass


def main():
    config = dotenv.dotenv_values()
    asyncio.run(async_main(config))
    print("see you next time!")
