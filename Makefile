SED=$(shell command -v gsed || command -v sed)
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
OUTPUTS = $(patsubst %,%/trivy-mcp,$(PLATFORMS))


.PHONY: clean
clean:
	@rm -rf trivy-mcp*

.PHONY: test
test:
	@echo "Running tests..."
	@trivy_version=$$(cat go.mod | grep 'github.com/aquasecurity/trivy v' | awk '{ print $$2}') ;\
	echo Current trivy version: $$trivy_version ;\
	GOEXPERIMENT=jsonv2 go test -v ./... -ldflags "-X github.com/aquasecurity/trivy-mcp/pkg/version.TrivyVersion=$${trivy_version}" -coverprofile=coverage.out -covermode=atomic
	@echo "Tests completed."

.PHONY: coverage
coverage:
	@echo "Generating coverage report..."
	@trivy_version=$$(cat go.mod | grep 'github.com/aquasecurity/trivy v' | awk '{ print $$2}') ;\
	echo Current trivy version: $$trivy_version ;\
	GOEXPERIMENT=jsonv2 go test -v ./... -ldflags "-X github.com/aquasecurity/trivy-mcp/pkg/version.TrivyVersion=$${trivy_version}" -coverprofile=coverage.out -covermode=atomic
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: build
build: clean $(OUTPUTS)
%/trivy-mcp:
	@[ $$NEW_VERSION ] || ( echo "env 'NEW_VERSION' is not set"; exit 1 );
	@trivy_version=$$(cat go.mod | grep 'github.com/aquasecurity/trivy v' | awk '{print $$2}'); \
	if [ -z "$$trivy_version" ]; then \
		echo "Trivy version not found in go.mod"; \
		exit 1; \
	fi; \
	echo Current trivy version: $$trivy_version; \
	echo "Building for $*..."; \
	GOOS=$(word 1,$(subst /, ,$*)); \
	GOARCH=$(word 2,$(subst /, ,$*)); \
	GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags "-s -w -X github.com/aquasecurity/trivy-mcp/pkg/version.Version=v$${NEW_VERSION} -X github.com/aquasecurity/trivy-mcp/pkg/version.TrivyVersion=$${trivy_version}" -o trivy-mcp ./cmd/trivy-mcp/main.go; \
	if [ $$GOOS = "windows" ]; then \
		mv trivy-mcp trivy-mcp.exe; \
		tar -czf trivy-mcp-$$GOOS-$$GOARCH.tar.gz plugin.yaml trivy-mcp.exe LICENSE > /dev/null; \
		rm trivy-mcp.exe; \
	else \
		tar -czf trivy-mcp-$$GOOS-$$GOARCH.tar.gz plugin.yaml trivy-mcp LICENSE > /dev/null; \
		rm trivy-mcp; \
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

.PHONY: install
install: add-plugin-manifest
	@echo "Installing plugin..."
	@trivy_version=$$(cat go.mod | grep 'github.com/aquasecurity/trivy v' | awk '{ print $$2}') ;\
	echo Current trivy version: $$trivy_version ;\
	GOEXPERIMENT=jsonv2 go build -ldflags "-s -w -X github.com/aquasecurity/trivy-mcp/pkg/version.TrivyVersion=$${trivy_version}" -o ~/.trivy/plugins/mcp/trivy-mcp ./cmd/trivy-mcp/main.go;
	@echo "Plugin installed successfully."

.PHONY: run
run:
	@trivy_version=$$(cat go.mod | grep 'github.com/aquasecurity/trivy v' | awk '{ print $$2}') ;\
	echo Current trivy version: $$trivy_version ;\
	GOEXPERIMENT=jsonv2 go build  -ldflags "-s -w -X github.com/aquasecurity/trivy-mcp/pkg/version.TrivyVersion=$${trivy_version}" -o trivy-mcp ./cmd/trivy-mcp/main.go;
	@./trivy-mcp help

.PHONY: format
format:
	@echo "Running gofmt..."
	@gofmt -w .  

.PHONY: lint
lint:
	@which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.4.0
	@golangci-lint run --timeout 3m --verbose

.PHONY: bump-manifest
bump-manifest:
	@current_version=$$(cat plugin.yaml | grep 'version' | awk '{ print $$2}' | tr -d '"') ;\
	NEW_VERSION=$$(echo $$current_version | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}') ;\
	echo Current version: $$current_version ;\
	echo New version: $$NEW_VERSION ;\
	$(SED) -i -e "s/$$current_version/$$NEW_VERSION/g" plugin.yaml ;