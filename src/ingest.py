import sqlite3
from typing import Any
import aiohttp
import asyncio
import dotenv
import json
import logging

logger = logging.getLogger(__name__)


async def ingest_jetstream(config: dict[str, str | None]):
    socket = f"wss://{config['JETSTREAM_URL']}/subscribe"
    socket += "?wantedCollections=at.ligo.*"
    logger.info(f"connecting to {socket}")
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(socket) as ws:
            async for message in ws:
                if message.type == aiohttp.WSMsgType.TEXT:
                    json = message.json()
                    did = json["did"]
                    if json["kind"] == "commit":
                        handle_commit(did, json["commit"], config)
                else:
                    continue


def handle_commit(did: str, commit: dict[str, Any], config: dict[str, str | None]):
    is_delete: bool = commit["operation"] == "delete"
    collection: str = commit["collection"]
    rkey: str = commit["rkey"]

    if rkey != "self":
        return

    db = get_database(config)
    if not db:
        return
    cursor = db.cursor()

    prefix: str | None = None
    type: str | None = None
    match collection:
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

    if is_delete:
        logger.debug(f"deleting {prefix} for {did}")
        _ = cursor.execute(
            "delete from keyval where prefix = ? and key = ?",
            (prefix, did),
        )
    else:
        logger.debug(f"creating or updating {prefix} for {did}")
        record: dict[str, str] = commit["record"]
        if record["$type"] != type:
            return
        content = json.dumps(record)
        _ = cursor.execute(
            "insert or replace into keyval values (?, ?, ?)",
            (prefix, did, content),
        )

    db.commit()
    cursor.close()
    db.close()


def get_database(config: dict[str, str | None]) -> sqlite3.Connection | None:
    database_name = config.get("FLASK_DATABASE_URL", "ligoat.db")
    if not database_name:
        return None
    return sqlite3.connect(database_name)


async def main(config: dict[str, str | None]):
    try:
        await ingest_jetstream(config)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    config = dotenv.dotenv_values()
    asyncio.run(main(config))
    print("see you next time!")
