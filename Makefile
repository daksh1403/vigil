.PHONY: help up down dev build rebuild migrate seed-demo lint typecheck test shell logs ps \
        ollama-pull clean fmt backend-shell worker-shell frontend-shell

SHELL := /bin/bash
COMPOSE := docker compose
COMPOSE_DEV := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

up: ## Start full stack (prod-like)
	$(COMPOSE) up -d

dev: ## Start stack with hot reload
	$(COMPOSE_DEV) up -d

down: ## Stop stack
	$(COMPOSE) down

build: ## Build all images
	$(COMPOSE) build

rebuild: ## Rebuild without cache
	$(COMPOSE) build --no-cache

migrate: ## Apply DB migrations
	$(COMPOSE) exec backend alembic upgrade head || true
	$(COMPOSE) exec backend python -m app.db_init

seed-demo: ## Seed demo project + sample findings
	$(COMPOSE) exec backend python -m app.seed

lint: ## Lint backend + frontend
	$(COMPOSE) exec backend ruff check . || true
	$(COMPOSE) exec backend mypy app || true
	$(COMPOSE) exec frontend npm run lint || true

typecheck: ## Type-check
	$(COMPOSE) exec backend mypy app || true
	$(COMPOSE) exec frontend npm run typecheck || true

test: ## Run all tests
	$(COMPOSE) exec backend pytest -q || true
	$(COMPOSE) exec frontend npm run test || true

shell: ## Shell into backend
	$(COMPOSE) exec backend bash

worker-shell: ## Shell into worker
	$(COMPOSE) exec worker bash

frontend-shell: ## Shell into frontend
	$(COMPOSE) exec frontend sh

logs: ## Tail all logs
	$(COMPOSE) logs -f --tail=100

ps: ## Show containers
	$(COMPOSE) ps

ollama-pull: ## Pull default LLM model into Ollama
	$(COMPOSE) exec ollama ollama pull tinyllama || true
	$(COMPOSE) exec ollama ollama pull nomic-embed-text || true

clean: ## Remove containers + volumes (DESTRUCTIVE)
	$(COMPOSE) down -v
	rm -rf backend/.pytest_cache backend/.ruff_cache frontend/.next frontend/node_modules

fmt: ## Format code
	$(COMPOSE) exec backend ruff format . || true
	$(COMPOSE) exec frontend npm run format || true
