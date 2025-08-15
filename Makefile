# Makefile for AIDA Permissions development

.PHONY: help install install-dev test lint format check clean build docs

help:
	@echo "Available commands:"
	@echo "  make install      - Install the package in production mode"
	@echo "  make install-dev  - Install the package in development mode with dev dependencies"
	@echo "  make test        - Run tests with pytest"
	@echo "  make lint        - Run ruff linter"
	@echo "  make format      - Format code with ruff"
	@echo "  make check       - Run all checks (lint + format check)"
	@echo "  make clean       - Remove build artifacts and cache files"
	@echo "  make build       - Build distribution packages"
	@echo "  make docs        - Generate documentation"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pip install pre-commit
	pre-commit install

test:
	pytest

test-verbose:
	pytest -vvs

test-coverage:
	pytest --cov=aida_permissions --cov-report=html --cov-report=term

lint:
	ruff check aida_permissions tests

lint-fix:
	ruff check --fix aida_permissions tests

format:
	ruff format aida_permissions tests

format-check:
	ruff format --check aida_permissions tests

check: lint-fix format
	@echo "✅ All checks passed!"

check-strict:
	ruff check aida_permissions tests
	ruff format --check aida_permissions tests
	pytest

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

build: clean
	python setup.py sdist bdist_wheel

docs:
	@echo "Generating documentation..."
	@# Add documentation generation commands here

migrate:
	python manage.py makemigrations aida_permissions
	python manage.py migrate

runserver:
	python manage.py runserver

shell:
	python manage.py shell_plus

# Ruff specific commands
ruff-stats:
	ruff check --statistics aida_permissions tests

ruff-explain:
	@echo "To explain a specific rule, run: ruff rule <RULE_CODE>"
	@echo "Example: ruff rule E501"

ruff-diff:
	ruff check --diff aida_permissions tests

ruff-unsafe-fixes:
	ruff check --fix --unsafe-fixes aida_permissions tests

# Pre-commit hooks
pre-commit-install:
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-run:
	pre-commit run --all-files

pre-commit-update:
	pre-commit autoupdate