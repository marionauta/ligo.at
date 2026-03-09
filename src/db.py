import sqlite3
from logging import Logger
from sqlite3 import Connection
from typing import Generic, Literal, cast, override

from flask import Flask, g

from src.atproto.kv import KV as BaseKV
from src.atproto.kv import K, V


class KV(BaseKV, Generic[K, V]):
    db: Connection
    logger: Logger
    prefix: str

    def __init__(self, app: Connection | Flask, logger: Logger, prefix: str):
        self.db = app if isinstance(app, Connection) else get_db(app, name="keyval")
        self.logger = logger
        self.prefix = prefix

    @override
    def get(self, key: K) -> V | None:
        cursor = self.db.cursor()
        row: dict[str, str] | None = cursor.execute(
            "select value from keyval where prefix = ? and key = ?",
            (self.prefix, key),
        ).fetchone()
        if row is not None:
            self.logger.debug(f"returning cached {self.prefix}({key})")
            return cast(V, row["value"])
        return None

    @override
    def set(self, key: K, value: V):
        self.logger.debug(f"caching {self.prefix}({key}): {value}")
        cursor = self.db.cursor()
        _ = cursor.execute(
            "insert or replace into keyval (prefix, key, value) values (?, ?, ?)",
            (self.prefix, key, value),
        )
        self.db.commit()


type DatabaseName = Literal["config"] | Literal["keyval"]


def get_db(app: Flask, name: DatabaseName) -> sqlite3.Connection:
    global_key = f"{name}_db"
    db: sqlite3.Connection | None = g.get(global_key, None)
    if db is None:
        db_path: str = app.config[f"{name.upper()}_DB_URL"]
        db = sqlite3.connect(db_path, check_same_thread=False)
        setattr(g, global_key, db)
        # return rows as dict-like objects
        db.row_factory = sqlite3.Row
    return db


def close_db_connection(_exception: BaseException | None):
    for name in ["keyval", "config"]:
        db: sqlite3.Connection | None = g.pop(f"{name}_db", None)
        if db is not None:
            db.close()


def init_db(app: Flask, name: DatabaseName) -> None:
    with app.app_context():
        db = get_db(app, name)
        with app.open_resource(f"{name}.sql", mode="r") as schema:
            _ = db.cursor().executescript(schema.read())
        db.commit()
