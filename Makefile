# SBOM HTML Generator Makefile
# Provides convenient commands for running the SBOM generator locally

# Default configuration
PYTHON := python3
PIP := pip3
VENV_DIR := venv
SCRIPT := sbom_generator.py
DEFAULT_IMAGE := alfresco/alfresco-content-repository-community:25.1.0
OUTPUT_DIR := reports
TEMPLATE_DIR := templates

# Colors for output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m # No Color

# Default target
.PHONY: help
help: ## Show this help message
	@echo "$(BLUE)SBOM HTML Generator - Available Commands$(NC)"
	@echo "========================================"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make setup                    # Install dependencies"
	@echo "  make run                      # Run with default Ubuntu image"
	@echo "  make run IMAGE=nginx:alpine   # Run with custom image"
	@echo "  make demo                     # Run demos with popular images"

# Setup and installation
.PHONY: setup
setup: ## Install Python dependencies and Syft
	@echo "$(BLUE)Setting up SBOM Generator environment...$(NC)"
	@$(PYTHON) -m venv $(VENV_DIR) || (echo "$(RED)Failed to create virtual env$(NC)" && exit 1)
	@echo "$(GREEN) Virtual environment created$(NC)"
	@. $(VENV_DIR)/bin/activate && $(PIP) install --upgrade pip
	@. $(VENV_DIR)/bin/activate && $(PIP) install requests
	@echo "$(GREEN) Python dependencies installed$(NC)"
	@$(MAKE) install-syft
	@$(MAKE) create-dirs
	@echo "$(GREEN)🎉 Setup complete! Run 'make run' to test$(NC)"

.PHONY: install-syft
install-syft: ## Install Syft SBOM tool
	@echo "$(BLUE)Installing Syft...$(NC)"
	@if command -v syft >/dev/null 2>&1; then \
		echo "$(GREEN)✓ Syft already installed: $$(syft version)$(NC)"; \
	else \
		echo "$(YELLOW)Installing Syft via curl...$(NC)"; \
		curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin || \
		(echo "$(RED)Failed to install Syft. Please install manually from https://github.com/anchore/syft$(NC)" && exit 1); \
		echo "$(GREEN)✓ Syft installed successfully$(NC)"; \
	fi

.PHONY: create-dirs
create-dirs: ## Create necessary directories
	@mkdir -p $(OUTPUT_DIR) $(TEMPLATE_DIR)
	@echo "$(GREEN)✓ Created directories: $(OUTPUT_DIR), $(TEMPLATE_DIR)$(NC)"

# Main execution commands
.PHONY: run
run: check-deps ## Run SBOM generator with default or specified image
	@$(eval IMAGE ?= $(DEFAULT_IMAGE))
	@$(eval OUTPUT ?= $(OUTPUT_DIR)/sbom_$(shell echo $(IMAGE) | tr '/:' '_').html)
	@echo "$(BLUE)Generating SBOM for image: $(IMAGE)$(NC)"
	@. $(VENV_DIR)/bin/activate && $(PYTHON) $(SCRIPT) $(IMAGE) - $(OUTPUT)
	@echo "$(GREEN)✓ Report generated: $(OUTPUT)$(NC)"
	@$(MAKE) open-report OUTPUT=$(OUTPUT)

.PHONY: run-with-template
run-with-template: check-deps ## Run with custom template (usage: make run-with-template IMAGE=image TEMPLATE=file)
	@$(eval IMAGE ?= $(DEFAULT_IMAGE))
	@$(eval TEMPLATE ?= $(TEMPLATE_DIR)/custom.tmpl)
	@$(eval OUTPUT ?= $(OUTPUT_DIR)/sbom_$(shell echo $(IMAGE) | tr '/:' '_')_custom.html)
	@if [ ! -f $(TEMPLATE) ]; then \
		echo "$(RED)Template file not found: $(TEMPLATE)$(NC)"; \
		echo "$(YELLOW)Create a template or use 'make create-template'$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Generating SBOM for $(IMAGE) with template $(TEMPLATE)$(NC)"
	@. $(VENV_DIR)/bin/activate && $(PYTHON) $(SCRIPT) $(IMAGE) $(TEMPLATE) $(OUTPUT)
	@echo "$(GREEN)✓ Report generated: $(OUTPUT)$(NC)"

# Templates
.PHONY: create-template
create-template: ## Create a sample custom template
	@echo "$(BLUE)Creating flat template for parser compatibility...$(NC)"
	@mkdir -p $(TEMPLATE_DIR)
	@printf '{{- range .artifacts}}\n'\
'{{ .name }}:{{ .version }}:{{ .purl }} - {{ range .licenses }}{{ .value }}{{ end }}\n'\
'{{- end}}' > $(TEMPLATE_DIR)/detailed.tmpl
	@echo "$(GREEN)✓ Flat template created: $(TEMPLATE_DIR)/detailed.tmpl$(NC)"
	@echo "$(YELLOW)Usage: make run-with-template TEMPLATE=$(TEMPLATE_DIR)/detailed.tmpl$(NC)"

.PHONY: list-templates
list-templates: ## List available templates
	@echo "$(BLUE)Available templates:$(NC)"
	@if [ -d $(TEMPLATE_DIR) ] && [ "$$(ls -A $(TEMPLATE_DIR))" ]; then \
		ls -la $(TEMPLATE_DIR)/*.tmpl 2>/dev/null || echo "$(YELLOW)No .tmpl files found$(NC)"; \
	else \
		echo "$(YELLOW)No templates directory or files found$(NC)"; \
		echo "$(YELLOW)Run 'make create-template' to create a sample$(NC)"; \
	fi

# Utility commands
.PHONY: open-report
open-report: ## Open the most recent report in browser
	@$(eval OUTPUT ?= $(shell ls -t $(OUTPUT_DIR)/*.html 2>/dev/null | head -n1))
	@if [ -n "$(OUTPUT)" ] && [ -f "$(OUTPUT)" ]; then \
		echo "$(BLUE)Opening report: $(OUTPUT)$(NC)"; \
		if command -v xdg-open >/dev/null 2>&1; then \
			xdg-open $(OUTPUT); \
		elif command -v open >/dev/null 2>&1; then \
			open $(OUTPUT); \
		elif command -v start >/dev/null 2>&1; then \
			start $(OUTPUT); \
		else \
			echo "$(YELLOW)Please open $(OUTPUT) manually in your browser$(NC)"; \
		fi; \
	else \
		echo "$(RED)No report found to open$(NC)"; \
	fi

.PHONY: list-reports
list-reports: ## List generated reports
	@echo "$(BLUE)Generated SBOM reports:$(NC)"
	@if [ -d $(OUTPUT_DIR) ] && [ "$$(ls -A $(OUTPUT_DIR))" ]; then \
		ls -lah $(OUTPUT_DIR)/*.html 2>/dev/null | awk '{print "$(GREEN)" $$9 "$(NC) (" $$5 ", " $$6 " " $$7 " " $$8 ")"}' || \
		echo "$(YELLOW)No HTML reports found$(NC)"; \
	else \
		echo "$(YELLOW)No reports directory or files found$(NC)"; \
	fi

.PHONY: clean-reports
clean-reports: ## Clean generated reports
	@echo "$(BLUE)Cleaning generated reports...$(NC)"
	@rm -rf $(OUTPUT_DIR)/*.html 2>/dev/null || true
	@echo "$(GREEN)✓ Reports cleaned$(NC)"

.PHONY: check-deps
check-deps: ## Check if dependencies are installed
	@if [ ! -d $(VENV_DIR) ]; then \
		echo "$(RED)Virtual environment not found. Run 'make setup' first$(NC)"; \
		exit 1; \
	fi
	@if ! command -v syft >/dev/null 2>&1; then \
		echo "$(RED)Syft not found. Run 'make install-syft' or 'make setup'$(NC)"; \
		exit 1; \
	fi
	@if [ ! -f $(SCRIPT) ]; then \
		echo "$(RED)$(SCRIPT) not found in current directory$(NC)"; \
		exit 1; \
	fi

.PHONY: info
info: ## Show environment information
	@echo "$(BLUE)SBOM Generator Environment Info$(NC)"
	@echo "==============================="
	@echo "Python: $$($(PYTHON) --version 2>&1 || echo 'Not found')"
	@echo "Syft: $$(syft version 2>&1 | head -n1 || echo 'Not found')"
	@echo "Virtual env: $(if $(wildcard $(VENV_DIR)),$(GREEN)Found$(NC),$(RED)Not found$(NC))"
	@echo "Script: $(if $(wildcard $(SCRIPT)),$(GREEN)Found$(NC),$(RED)Not found$(NC))"
	@echo "Output dir: $(OUTPUT_DIR)"
	@echo "Template dir: $(TEMPLATE_DIR)"
	@echo ""
	@echo "$(BLUE)Docker images for testing:$(NC)"
	@docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" 2>/dev/null | head -n10 || \
		echo "$(YELLOW)Docker not available or no images found$(NC)"

# Development and maintenance
.PHONY: lint
lint: ## Run basic Python linting
	@if [ -d $(VENV_DIR) ]; then \
		echo "$(BLUE)Running Python syntax check...$(NC)"; \
		. $(VENV_DIR)/bin/activate && $(PYTHON) -m py_compile $(SCRIPT) && \
		echo "$(GREEN)✓ Python syntax OK$(NC)"; \
	else \
		echo "$(YELLOW)Virtual environment not found, skipping lint$(NC)"; \
	fi

.PHONY: clean
clean: clean-reports ## Clean all generated files and virtual environment
	@echo "$(BLUE)Cleaning up...$(NC)"
	@rm -rf $(VENV_DIR)
	@rm -rf __pycache__ *.pyc
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

.PHONY: reinstall
reinstall: clean setup ## Clean and reinstall everything
	@echo "$(GREEN)✓ Reinstallation complete$(NC)"

# GitHub token setup
.PHONY: setup-github-token
setup-github-token: ## Help setup GitHub token for better API limits
	@echo "$(BLUE)GitHub Token Setup$(NC)"
	@echo "=================="
	@echo "To improve GitHub API rate limits, set up a personal access token:"
	@echo ""
	@echo "1. Go to: https://github.com/settings/tokens"
	@echo "2. Generate a new token (classic)"
	@echo "3. Select 'public_repo' scope"
	@echo "4. Copy the token and run:"
	@echo "   $(YELLOW)export GITHUB_TOKEN=your_token_here$(NC)"
	@echo "5. Add it to your ~/.bashrc or ~/.zshrc for persistence"
	@echo ""
	@if [ -n "$$GITHUB_TOKEN" ]; then \
		echo "$(GREEN)✓ GITHUB_TOKEN is currently set$(NC)"; \
	else \
		echo "$(YELLOW)⚠ GITHUB_TOKEN is not set$(NC)"; \
	fi