SED=$(shell command -v gsed || command -v sed)
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
OUTPUTS = $(patsubst %,%/trivy-plugin-mcp,$(PLATFORMS))

.PHONY: clean
clean:
	rm -rf trivy-plugin-mcp*

.PHONY: build
build: clean $(OUTPUTS)

%/trivy-plugin-mcp:
	@[ $$NEW_VERSION ] || ( echo "env 'NEW_VERSION' is not set"; exit 1 )
	@echo "Building for $*..."
	@mkdir -p $(dir $@); \
	GOOS=$(word 1,$(subst /, ,$*)); \
	GOARCH=$(word 2,$(subst /, ,$*)); \
	CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags "-s -w -X github.com/aquasecurity/trivy-plugin-mcp/pkg/version.Version=$${NEW_VERSION}" -o mcp ./cmd/trivy-mcp/main.go; \
	if [ $$GOOS = "windows" ]; then \
		mv mcp mcp.exe; \
		tar -czf trivy-plugin-mcp-$$GOOS-$$GOARCH.tar.gz plugin.yaml mcp.exe LICENSE > /dev/null; \
		rm mcp.exe; \
	else \
		tar -czf trivy-plugin-mcp-$$GOOS-$$GOARCH.tar.gz plugin.yaml mcp LICENSE > /dev/null; \
		rm mcp; \
	fi

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

.PHONY: lint
lint:
	@which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.2
	@golangci-lint run --timeout 3m --verbose

.PHONY: bump-manifest
bump-manifest:
	@[ $$NEW_VERSION ] || ( echo "env 'NEW_VERSION' is not set"; exit 1 )
	@current_version=$$(cat plugin.yaml | grep 'version' | awk '{ print $$2}' | tr -d '"') ;\
	echo Current version: $$current_version ;\
	echo New version: $$NEW_VERSION ;\
	$(SED) -i -e "s/$$current_version/$$NEW_VERSION/g" plugin.yaml ;\