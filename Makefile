.PHONY: help install dev-install test lint format typecheck audit run docker-build docker-run clean

PYTHON ?= python
VENV_BIN ?= .venv/bin
ifeq ($(OS),Windows_NT)
    VENV_BIN = .venv/Scripts
endif

help:
	@echo "ZenShield Development & Ops Targets:"
	@echo "  make install        Install production dependencies"
	@echo "  make dev-install    Install all development dependencies"
	@echo "  make test           Run unit and integration test suites"
	@echo "  make lint           Check linting and formatting with Ruff"
	@echo "  make format         Auto-format code with Ruff"
	@echo "  make typecheck      Run static type checking with Mypy"
	@echo "  make audit          Run security vulnerability scan with pip-audit"
	@echo "  make run            Run local development server"
	@echo "  make docker-build   Build production Docker container"
	@echo "  make docker-run     Run container via Docker Compose"
	@echo "  make clean          Clean temporary caches and artifacts"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install .

dev-install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(VENV_BIN)/pytest tests/ -v

lint:
	$(VENV_BIN)/ruff check src/ tests/
	$(VENV_BIN)/ruff format --check src/ tests/

format:
	$(VENV_BIN)/ruff format src/ tests/
	$(VENV_BIN)/ruff check --fix src/ tests/

typecheck:
	$(VENV_BIN)/mypy src/zenshield

audit:
	$(VENV_BIN)/pip-audit

run:
	$(VENV_BIN)/uvicorn zenshield.main:app --host 0.0.0.0 --port 8000 --reload

docker-build:
	docker build -t zenshield:2.0.0 .

docker-run:
	docker-compose up -d

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
