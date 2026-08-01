.PHONY: install install-dev test lint format

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	pytest

lint:
	ruff check .
	mypy .

format:
	black .
	ruff check --fix .
