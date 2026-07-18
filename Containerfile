FROM ghcr.io/astral-sh/uv:debian-slim@sha256:53476714c941e4fe1ec3d7c24c405681752365d882d165a848bc22d84f19106a

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates supervisor && apt clean

WORKDIR /app
COPY . .

ENV UV_NO_DEV=1
RUN uv sync --locked && uv cache clean

RUN mkdir -p /data

ENV FLASK_KEYVAL_DB_URL=/data/keyval.db
ENV FLASK_CONFIG_DB_URL=/data/config.db
ENV PORT=80
EXPOSE 80

CMD [ "supervisord", "-c", "/app/supervisord.conf" ]
