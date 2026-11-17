PY ?= .venv/bin/python
export PYTHONPATH := src

.PHONY: setup test lint fmt validate tflint checkov policies plan all

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

fmt:
	terraform -chdir=terraform fmt -recursive -check

validate:
	terraform -chdir=terraform init -backend=false -input=false >/dev/null
	terraform -chdir=terraform validate

tflint:
	cd terraform && tflint --init >/dev/null && tflint --format compact

checkov:
	.venv/bin/checkov -d terraform --framework terraform --compact

policies:
	$(PY) scripts/lint_policies.py

plan:
	./scripts/offline-plan.sh

all: lint fmt validate tflint policies plan test checkov
