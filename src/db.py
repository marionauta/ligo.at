from abc import ABC, abstractmethod
from typing import override
from flask import Flask, g

import sqlite3
from sqlite3 import Connection


class KV(ABC):
    @abstractmethod
    def get(self, key: str) -> str | None:
        pass

    @abstractmethod
    def set(self, key: str, value: str):
        pass


class Keyval(KV):
    db: Connection
    prefix: str

    def __init__(self, app: Flask, prefix: str):
        self.db = get_db(app)
        self.prefix = prefix

    @override
    def get(self, key: str) -> str | None:
        cursor = self.db.cursor()
        row = cursor.execute(
            "select value from keyval where prefix = ? and key = ?",
            (self.prefix, key),
        ).fetchone()
        return None if row is None else row["value"]

    @override
    def set(self, key: str, value: str):
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
        db = g.db = sqlite3.connect(db_path)
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
