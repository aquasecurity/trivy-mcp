.PHONY: add-plugin-manifest
add-plugin-manifest:
	@echo "Checking if plugin manifest exists..."
	@if [ ! -f ~/.trivy/plugins/mcp/plugin.yaml ]; then \
		echo "Plugin manifest not found. Creating..."; \
		mkdir -p ~/.trivy/plugins/mcp; \
		cp plugin.yaml ~/.trivy/plugins/mcp/plugin.yaml; \
		echo "Plugin manifest created."; \
	else \
		echo "Plugin manifest already exists."; \
	fi

.PHONY: install-plugin
install-plugin: add-plugin-manifest
	@echo "Installing plugin..."
	@go build -o ~/.trivy/plugins/mcp/mcp ./cmd/trivy-mcp
	@echo "Plugin installed successfully."

.PHONY: run
run:
	@echo "Running plugin code as 'trivy mcp -t sse -d'..."
	@go run ./cmd/trivy-mcp -t sse -d