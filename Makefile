.PHONY: debug
debug:
	uv run -- flask --app 'src.main' run --debug -h '0.0.0.0' -p 8080

.PHONY: run
run:
	uv run -- gunicorn --bind ':$(PORT)' 'src.main:app'
