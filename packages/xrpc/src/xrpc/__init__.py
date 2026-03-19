from urllib.parse import urljoin

from aiohttp.client import ClientSession
from flask import Blueprint, current_app, request

xrpc = Blueprint("xrpc", __name__, url_prefix="/xrpc")


@xrpc.get("/app.bsky.actor.searchActorsTypeahead")
async def search_actors_typeahead():
    client_header = request.headers.get("X-Client")
    if not client_header:
        return ("missing X-Client header", 400)
    base = "https://typeahead.waow.tech"
    url = urljoin(base, "xrpc/app.bsky.actor.searchActorsTypeahead")
    url += f"?{request.query_string.decode('utf-8')}"
    async with ClientSession() as client:
        if not current_app.debug:
            client.headers.add("X-Client", client_header)
        async with client.get(url) as typeahead_response:
            response = await typeahead_response.json()
            status = 200
            try:
                actors = [
                    {"avatar": actor.get("avatar"), "handle": actor["handle"]}
                    for actor in response["actors"]
                ]
                response = {
                    "actors": actors,
                }
            except (KeyError, TypeError) as error:
                current_app.logger.error(error)
                response = {"actors": []}
                status = 500
            return (response, status)
