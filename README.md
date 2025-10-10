# ligo.at

A decentralized links page powered by the [AT Protocol][atproto].

## dependencies

Install [uv][uv] and run `uv sync`.

## generate secrets

Use the `generate_secrets.py` script or run `make .env`.

## run

Either start a debug server with `make debug` or a production one with `make run`. Production needs the `PORT` environment variable.

[atproto]: https://atproto.com
[uv]: https://docs.astral.sh/uv/
