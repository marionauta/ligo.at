from flask import Flask, g

import sqlite3


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
