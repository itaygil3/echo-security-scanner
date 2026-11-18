.PHONY: help install lint format test up down logs ps clean

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

install:  ## Install dev dependencies into the active virtualenv
	pip install -r requirements-dev.txt

lint:  ## Run ruff lint + format check
	ruff check .
	ruff format --check .

format:  ## Auto-format and fix lint issues
	ruff format .
	ruff check --fix .

test:  ## Run unit tests
	pytest

up:  ## Build and start the full stack
	docker compose up --build -d

down:  ## Stop the stack
	docker compose down

logs:  ## Tail logs of all services
	docker compose logs -f

ps:  ## Show service status
	docker compose ps

clean:  ## Stop the stack and delete volumes (re-runs DB init + seed on next start)
	docker compose down -v