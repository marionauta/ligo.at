.PHONY: debug
debug:
	uv run -- flask --app 'src.main' run --debug -h '0.0.0.0' -p 8080

.PHONY: tunnel
tunnel:
	ssh -R 3000:localhost:8080 $(SERVER)

.PHONY: run
run:
	uv run -- dotenv run -- gunicorn

.PHONY: ingestor
ingestor:
	uv run -- ingestor

.env:
	uv run -- etc/generate_secrets.py >> .env
