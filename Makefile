# VULNEX AI - Unified Development Makefile
#
# Commands to run the complete integrated application locally.
#
# Prerequisites: Python 3.11+, Node.js 18+, npm

.PHONY: help install install-backend install-frontend run-backend run-frontend run-demo test build-frontend clean docker-up docker-down

help: ## Show available make targets
	@echo "VULNEX AI - Unified Development Commands"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------
# Installation
# ---------------------------------------------------------------
install: install-backend install-frontend ## Install all dependencies (backend + frontend)

install-backend: ## Install Python backend dependencies
	pip install -r backend/requirements.txt

install-frontend: ## Install Node.js frontend dependencies
	cd frontend && npm ci

# ---------------------------------------------------------------
# Local development servers
# ---------------------------------------------------------------
run-backend: ## Start FastAPI backend on http://localhost:8000
	python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

run-frontend: ## Start Next.js frontend on http://localhost:3000
	cd frontend && npm run dev

run-demo: ## Start vulnerable demo project on http://localhost:8001
	cd demo-project && python -m uvicorn app:app --host 0.0.0.0 --port 8001

run: ## Start all services (backend + frontend) in parallel
	@echo "Starting backend on http://localhost:8000"
	@echo "Starting frontend on http://localhost:3000"
	@echo "Starting demo project on http://localhost:8001"
	@echo ""
	@echo "Open http://localhost:3000 in your browser"

# ---------------------------------------------------------------
# Testing
# ---------------------------------------------------------------
test: ## Run backend unit tests
	python -m pytest backend/tests -v

test-frontend: ## Run frontend typecheck / lint
	cd frontend && npm run lint

# ---------------------------------------------------------------
# Build
# ---------------------------------------------------------------
build-frontend: ## Build Next.js frontend for production
	cd frontend && npm run build

build: build-frontend ## Build all production artifacts

# ---------------------------------------------------------------
# Docker
# ---------------------------------------------------------------
docker-up: ## Start all services via Docker Compose
	docker-compose up --build

docker-down: ## Stop all Docker Compose services
	docker-compose down

docker-logs: ## Follow Docker Compose logs
	docker-compose logs -f

# ---------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------
clean: ## Remove local build artifacts and cache
	rm -rf backend/__pycache__ backend/app/__pycache__ backend/app/api/__pycache__
	rm -rf backend/app/models/__pycache__ backend/app/services/__pycache__
	rm -rf backend/app/services/scanners/__pycache__ backend/app/demo_data/__pycache__
	rm -rf backend/tests/__pycache__
	rm -rf frontend/.next frontend/node_modules
	rm -rf .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
