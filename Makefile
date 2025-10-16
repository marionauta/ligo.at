.env:
	uv run -- etc/generate_secrets.py >> .env

.PHONY: debug
debug:
	uv run -- flask --app 'src.main' run --debug -h '0.0.0.0' -p 8080

.PHONY: run
run:
	uv run -- dotenv run -- gunicorn

.PHONY: ingestor
ingestor:
	uv run -- ingestor
