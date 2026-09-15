.PHONY: help build build-mobsf-owaspdc run test hooks-install services-up services-down compose-run compose-run-standalone compose-run-mobsf-owaspdc compose-down

# Image Variables
IMAGE_NAME ?= appcritiq-core
TAG ?= latest
MOBSF_API_KEY ?= appcritiq-local-mobsf-api-key
MODE ?= source

# Local Paths
PROJECT_PATH ?= $(shell pwd)
RESULTS_DIR ?= $(shell pwd)/scan-results
PHOENIX_SCAN_PATH ?= /workspace

help:
	@echo "AppcritIQ Core"
	@echo ""
	@echo "Targets:"
	@echo "  make build         Build the appcritiq-core image"
	@echo "  make build-mobsf-owaspdc"
	@echo "                     Build the appcritiq-core compose image with MobSF and NVD sidecars"
	@echo "  make run           Run a standalone docker run scan"
	@echo "  make services-up   Start the MobSF sidecar"
	@echo "  make services-down Stop the MobSF sidecar"
	@echo "  make compose-run   Build and run a scan with docker compose"
	@echo "  make compose-run-mobsf-owaspdc"
	@echo "                     Build and run a compose scan with MobSF and NVD sidecars"
	@echo "  make test          Run local pytest"
	@echo "  make hooks-install Install the repository pre-commit hook"
	@echo ""
	@echo "Examples:"
	@echo "  make run PROJECT_PATH=/path/to/project SCAN_FLAG=--native-ios-source-path"
	@echo "  make compose-run PROJECT_PATH=/path/to/project SCAN_FLAG=--native-ios-source-path"
	@echo "  make compose-run-mobsf-owaspdc PROJECT_PATH=/path/to/app.ipa SCAN_FLAG=--ios-binary-path"
	@echo "  make compose-run PROJECT_PATH=/path/to/app.ipa SCAN_FLAG=--ios-binary-path"

build:
	docker build \
		--pull \
		-t $(IMAGE_NAME):$(TAG) .

build-mobsf-owaspdc:
	docker compose build appcritiq-mobsf-owaspdc

run:
	@mkdir -p $(RESULTS_DIR)
	@if [ -z "$(SCAN_FLAG)" ]; then \
		echo "Set SCAN_FLAG to one AppcritIQ scan target flag"; \
		exit 1; \
	fi; \
	PROJECT_MOUNT_PATH="$(PROJECT_PATH)"; \
	SCAN_PATH="$(PHOENIX_SCAN_PATH)"; \
	if [ ! -e "$$PROJECT_MOUNT_PATH" ]; then \
		echo "PROJECT_PATH does not exist: $$PROJECT_MOUNT_PATH"; \
		echo "If the path contains spaces, wrap it in quotes."; \
		exit 1; \
	fi; \
	if [ -f "$$PROJECT_MOUNT_PATH" ]; then \
		if [ "$$SCAN_PATH" = "/workspace" ]; then \
			SCAN_PATH="/workspace/$$(basename "$$PROJECT_MOUNT_PATH")"; \
		fi; \
		PROJECT_MOUNT_PATH="$$(dirname "$$PROJECT_MOUNT_PATH")"; \
	fi; \
	echo "Mounting: $$PROJECT_MOUNT_PATH -> /workspace"; \
	echo "Scanning: $$SCAN_PATH"; \
	docker run --rm \
		-v "$$PROJECT_MOUNT_PATH:/workspace:ro" \
		-v "$(RESULTS_DIR):/app/results" \
		$(IMAGE_NAME):$(TAG) scan "$(SCAN_FLAG)" "$$SCAN_PATH" --output /app/results

services-up:
	PROJECT_PATH="$(PROJECT_PATH)" OUTPUT_PATH="$(RESULTS_DIR)" MOBSF_API_KEY="$(MOBSF_API_KEY)" docker compose up -d mobsf-scanner
	@echo "Waiting for MobSF scanner to become healthy..."
	@container_id=$$(docker compose ps -q mobsf-scanner); \
	for i in $$(seq 1 60); do \
		status=$$(docker inspect -f '{{.State.Health.Status}}' "$$container_id" 2>/dev/null || echo starting); \
		if [ "$$status" = "healthy" ]; then \
			echo "MobSF scanner is ready at http://localhost:8000"; \
			echo 'Run: MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"'; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "MobSF did not become healthy in time"; \
	exit 1

services-down:
	docker compose stop mobsf-scanner

compose-run:
	@mkdir -p "$(RESULTS_DIR)"
	@if [ -z "$(SCAN_FLAG)" ]; then \
		echo "Set SCAN_FLAG to one AppcritIQ scan target flag"; \
		exit 1; \
	fi; \
	PROJECT_MOUNT_PATH="$(PROJECT_PATH)"; \
	SCAN_PATH="$(PHOENIX_SCAN_PATH)"; \
	if [ ! -e "$$PROJECT_MOUNT_PATH" ]; then \
		echo "PROJECT_PATH does not exist: $$PROJECT_MOUNT_PATH"; \
		echo "If the path contains spaces, wrap it in quotes."; \
		exit 1; \
	fi; \
	if [ -f "$$PROJECT_MOUNT_PATH" ]; then \
		if [ "$$SCAN_PATH" = "/workspace" ]; then \
			SCAN_PATH="/workspace/$$(basename "$$PROJECT_MOUNT_PATH")"; \
		fi; \
		PROJECT_MOUNT_PATH="$$(dirname "$$PROJECT_MOUNT_PATH")"; \
	fi; \
	echo "Mounting: $$PROJECT_MOUNT_PATH -> /workspace"; \
	echo "Scanning: $$SCAN_PATH"; \
	OUTPUT_PATH="$(RESULTS_DIR)" \
	PROJECT_MOUNT_PATH="$$PROJECT_MOUNT_PATH" \
	SCAN_FLAG="$(SCAN_FLAG)" \
	PHOENIX_SCAN_PATH="$$SCAN_PATH" \
	GITLEAKS_SCAN_PATH="$${GITLEAKS_SCAN_PATH:-}" \
	docker compose up --build --exit-code-from appcritiq appcritiq

compose-run:
	@mkdir -p "$(RESULTS_DIR)"
	@if [ -z "$(SCAN_FLAG)" ]; then \
		echo "Set SCAN_FLAG to one AppcritIQ scan target flag"; \
		exit 1; \
	fi; \
	PROJECT_MOUNT_PATH="$(PROJECT_PATH)"; \
	SCAN_PATH="$(PHOENIX_SCAN_PATH)"; \
	if [ ! -e "$$PROJECT_MOUNT_PATH" ]; then \
		echo "PROJECT_PATH does not exist: $$PROJECT_MOUNT_PATH"; \
		echo "If the path contains spaces, wrap it in quotes."; \
		exit 1; \
	fi; \
	if [ -f "$$PROJECT_MOUNT_PATH" ]; then \
		if [ "$$SCAN_PATH" = "/workspace" ]; then \
			SCAN_PATH="/workspace/$$(basename "$$PROJECT_MOUNT_PATH")"; \
		fi; \
		PROJECT_MOUNT_PATH="$$(dirname "$$PROJECT_MOUNT_PATH")"; \
	fi; \
	echo "Mounting: $$PROJECT_MOUNT_PATH -> /workspace"; \
	echo "Scanning: $$SCAN_PATH"; \
	OUTPUT_PATH="$(RESULTS_DIR)" \
	PROJECT_MOUNT_PATH="$$PROJECT_MOUNT_PATH" \
	SCAN_FLAG="$(SCAN_FLAG)" \
	PHOENIX_SCAN_PATH="$$SCAN_PATH" \
	GITLEAKS_SCAN_PATH="$${GITLEAKS_SCAN_PATH:-}" \
	docker compose up --build --exit-code-from appcritiq appcritiq

compose-run-mobsf-owaspdc:
	@mkdir -p "$(RESULTS_DIR)"
	@if [ -z "$(SCAN_FLAG)" ]; then \
		echo "Set SCAN_FLAG to one AppcritIQ scan target flag"; \
		exit 1; \
	fi; \
	PROJECT_MOUNT_PATH="$(PROJECT_PATH)"; \
	SCAN_PATH="$(PHOENIX_SCAN_PATH)"; \
	if [ ! -e "$$PROJECT_MOUNT_PATH" ]; then \
		echo "PROJECT_PATH does not exist: $$PROJECT_MOUNT_PATH"; \
		echo "If the path contains spaces, wrap it in quotes."; \
		exit 1; \
	fi; \
	if [ -f "$$PROJECT_MOUNT_PATH" ]; then \
		if [ "$$SCAN_PATH" = "/workspace" ]; then \
			SCAN_PATH="/workspace/$$(basename "$$PROJECT_MOUNT_PATH")"; \
		fi; \
		PROJECT_MOUNT_PATH="$$(dirname "$$PROJECT_MOUNT_PATH")"; \
	fi; \
	echo "Mounting: $$PROJECT_MOUNT_PATH -> /workspace"; \
	echo "Scanning: $$SCAN_PATH"; \
	OUTPUT_PATH="$(RESULTS_DIR)" \
	PROJECT_MOUNT_PATH="$$PROJECT_MOUNT_PATH" \
	SCAN_FLAG="$(SCAN_FLAG)" \
	PHOENIX_SCAN_PATH="$$SCAN_PATH" \
	GITLEAKS_SCAN_PATH="$${GITLEAKS_SCAN_PATH:-}" \
	docker compose up --build --exit-code-from appcritiq-mobsf-owaspdc appcritiq-mobsf-owaspdc

compose-down:
	docker compose down

clean-docker:
	docker compose down --volumes --remove-orphans
	-docker stop $$(docker ps -aq)
	-docker rm $$(docker ps -aq)

test:
	@PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 uv run --no-project --with pytest pytest

hooks-install:
	@uv run pre-commit install --install-hooks
