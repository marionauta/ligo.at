import sqlite3
from logging import Logger
from sqlite3 import Connection
from typing import override

from flask import Flask, g

from src.atproto.kv import KV as BaseKV


class KV(BaseKV):
    db: Connection
    logger: Logger
    prefix: str

    def __init__(self, app: Connection | Flask, logger: Logger, prefix: str):
        self.db = app if isinstance(app, Connection) else get_db(app)
        self.logger = logger
        self.prefix = prefix

    @override
    def get(self, key: str) -> str | None:
        cursor = self.db.cursor()
        row: dict[str, str] | None = cursor.execute(
            "select value from keyval where prefix = ? and key = ?",
            (self.prefix, key),
        ).fetchone()
        if row is not None:
            self.logger.debug(f"returning cached {self.prefix}({key})")
            return row["value"]
        return None

    @override
    def set(self, key: str, value: str):
        self.logger.debug(f"caching {self.prefix}({key}): {value}")
        cursor = self.db.cursor()
        _ = cursor.execute(
            "insert or replace into keyval (prefix, key, value) values (?, ?, ?)",
            (self.prefix, key, value),
        )
        self.db.commit()


def get_db(app: Flask) -> sqlite3.Connection:
    db: sqlite3.Connection | None = g.get("db", None)
    if db is None:
        db_path: str = app.config.get("DATABASE_URL", "ligoat.db")
        db = g.db = sqlite3.connect(db_path, check_same_thread=False)
        # return rows as dict-like objects
        db.row_factory = sqlite3.Row
    return db


def close_db_connection(_exception: BaseException | None):
    db: sqlite3.Connection | None = g.get("db", None)
    if db is not None:
        db.close()


def init_db(app: Flask):
    with app.app_context():
        db = get_db(app)
        with app.open_resource("schema.sql", mode="r") as schema:
            _ = db.cursor().executescript(schema.read())
        db.commit()
