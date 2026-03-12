# =============================================================================
# XtractR Makefile — Forensic Workflow Automation
# =============================================================================

.PHONY: test test-benchmark test-determinism test-all lint clean docker-build docker-test golden help

PYTHON ?= python
PYTEST ?= $(PYTHON) -m pytest
FORENSIC_ENV = PYTHONHASHSEED=0 LC_ALL=C TZ=UTC

# --- Testing ---

test: ## Run core unit tests only
	$(FORENSIC_ENV) $(PYTEST) tests/ -v --ignore=tests/test_benchmark.py --ignore=tests/test_determinism.py --tb=short

test-benchmark: ## Run parser accuracy benchmark against golden dataset
	$(FORENSIC_ENV) $(PYTEST) tests/test_benchmark.py -v --tb=short

test-determinism: ## Run determinism test (dual-run byte comparison)
	$(FORENSIC_ENV) $(PYTEST) tests/test_determinism.py -v --tb=short

test-all: ## Run the complete test suite (core + benchmark + determinism)
	$(FORENSIC_ENV) $(PYTEST) tests/ -v --tb=short

# --- Golden Dataset ---

golden: ## Regenerate the golden dataset from scratch
	$(PYTHON) tests/generate_golden.py

# --- Docker ---

docker-build: ## Build the Docker image
	docker build -t xtractr:latest .

docker-test: docker-build ## Build and run tests inside Docker
	docker run --rm xtractr:latest make test-all

# --- Utilities ---

clean: ## Remove temporary and generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -rf .pytest_cache

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
