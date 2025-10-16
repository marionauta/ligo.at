# ligo.at

Decentralized and customizable links page on top of [AT Protocol][atproto].

## dependencies

Install [uv][uv] and run `uv sync`.

## generate secrets

Use the `etc/generate_secrets.py` script or run `make .env`.

## synchronization

`ligo.at` reads directly from the users' PDS. A small cache is used to serve profile pages quicker. The cache is updated on every profile write, and when requesting a profile with the `?reload` query parameter (any value, even empty). `ligo.at` also reads from the [Jetstream][jetstream], so updates made to a profile outside of `ligo.at` should also be available instantly.

## run

Either start a debug server with `make debug` or a production one with `make run`. Production needs the `PORT` environment variable.

The Jetstream ingestor can be started with `make ingestor`.

Some example configuration files are provided in the `etc` folder. They assume the code will live at `/var/www/ligoat`. Keep this in mind if you want to place it somewhere else.

- A `Caddyfile` that configures a [caddy][caddy] reverse proxy.
- Two systemd service files. They can be used to run both the server and the jetstream ingestor.

[atproto]: https://atproto.com
[caddy]: https://caddyserver.com/
[jetstream]: https://atproto.wiki/en/wiki/reference/networking/jetstream
[uv]: https://docs.astral.sh/uv/
