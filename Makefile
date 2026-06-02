# Makefile for PhantomFlow
# Usage: make <target>

.PHONY: help install db-init train train-quick serve api pipeline test docker-up docker-prod clean

PYTHON = python3
VENV   = venv
PIP    = $(VENV)/bin/pip

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✓ Installed. Copy .env.example to .env and configure."

db-init: ## Initialize PostgreSQL schema
	psql -h $${PG_HOST:-localhost} -U $${PG_USER:-phantom} \
	     -d $${PG_DB:-phantomflow} -f pipeline/schema.sql
	@echo "✓ Schema applied."

train: ## Full streaming training on all datasets (~3-4 hours)
	$(PYTHON) -m train.run_online

train-quick: ## Quick training run (100K rows per dataset, ~15 mins)
	$(PYTHON) -m train.run_online --max_rows 100000

mlflow: ## Launch MLflow experiment tracker
	mlflow ui --backend-store-uri sqlite:///mlflow.db
	@echo "→ http://localhost:5000"

serve: api pipeline ## Start API + pipeline together

api: ## Start the FastAPI server
	uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

pipeline: ## Start the Kafka-based detection pipeline
	$(PYTHON) -m pipeline.orchestrator

test: ## Run all tests
	pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/ -v --tb=short -k "not integration"

validate: ## Run pre-training validation pipeline
	$(PYTHON) -c "from train.validation_pipeline import RobustValidator; print('Validator ready')"

docker-up: ## Start dev infrastructure (Kafka, Redis, Postgres)
	docker compose -f docker/docker-compose.yml up -d
	@echo "✓ Dev infrastructure up. Wait ~30s for services to be ready."

docker-down: ## Stop dev infrastructure
	docker compose -f docker/docker-compose.yml down

docker-prod: ## Start production HA cluster
	docker compose -f docker/docker-compose.prod.yml up -d

docker-prod-down: ## Stop production cluster
	docker compose -f docker/docker-compose.prod.yml down

clean: ## Remove generated artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	rm -f eval/*.json
	@echo "✓ Cleaned."

clean-models: ## Remove trained models (forces retrain)
	rm -f models/*.pkl models/*.pt models/*.json
	@echo "✓ Models removed. Run 'make train-quick' to retrain."
