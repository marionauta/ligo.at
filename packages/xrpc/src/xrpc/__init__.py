from urllib.parse import urljoin

from aiohttp.client import ClientSession
from flask import Blueprint, request

xrpc = Blueprint("xrpc", __name__, url_prefix="/xrpc")


@xrpc.get("/app.bsky.actor.searchActorsTypeahead")
async def search_actors_typeahead():
    base = "https://public.api.bsky.app"
    url = urljoin(base, "xrpc/app.bsky.actor.searchActorsTypeahead")
    url += f"?{request.query_string.decode('utf-8')}"
    async with ClientSession() as client:
        async with client.get(url) as response:
            json = await response.json()
            try:
                res = [
                    {"avatar": actor["avatar"], "handle": actor["handle"]}
                    for actor in json["actors"]
                ]
                return {
                    "actors": res,
                }
            except KeyError:
                return json
