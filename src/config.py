from sqlite3 import Connection
from typing import NamedTuple

from flask import Flask

from src.db import get_db


class AuthServer(NamedTuple):
    name: str
    url: str


class Config:
    db: Connection

    def __init__(self, app: Flask):
        self.db = get_db(app, name="config")

    def auth_servers(self) -> list[AuthServer]:
        raw = (
            self.db.cursor()
            .execute("select name, url from pdss order by relevance desc")
            .fetchall()
        )
        return [AuthServer(*r) for r in raw]
