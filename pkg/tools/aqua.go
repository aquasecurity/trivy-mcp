package tools

import (
	"context"
	"errors"
	"os"
	"strings"

	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/mark3labs/mcp-go/mcp"
)

func (t *TrivyTools) scanWithAquaPlatform(ctx context.Context, args []string, creds creds.AquaCreds) (*mcp.CallToolResult, error) {

	logger := log.WithPrefix("aqua")
	logger.Debug("Scanning with args", log.Any("args", args))
	logger.Info("Using Aqua platform for scanning")

	// Set the region-specific URLs
	aquaURL, cspmURL := creds.GetUrls()
	if aquaURL == "" || cspmURL == "" {
		logger.Error("Failed to get Aqua URLs")
		return nil, errors.New("failed to get Aqua URLs, the region needs to be set")
	}
	logger.Debug("Aqua URL", log.Any("AquaURL", aquaURL))
	logger.Debug("CSPM URL", log.Any("CSPMURL", cspmURL))

	// Set the Aqua credentials in the environment variables
	os.Setenv("AQUA_KEY", creds.AquaKey)
	os.Setenv("AQUA_SECRET", creds.AquaSecret)
	os.Setenv("CSPM_URL", cspmURL)
	os.Setenv("AQUA_URL", aquaURL)

	defer func() {
		// clear the environment variables after the scan
		// This is important to avoid leaking credentials
		os.Unsetenv("AQUA_KEY")
		os.Unsetenv("AQUA_SECRET")
		os.Unsetenv("CSPM_URL")
		os.Unsetenv("AQUA_URL")
	}()

	logger.Debug("Environment", log.Any("ENV", os.Environ()))

	tempFile := filepath.Join(os.TempDir(), "trivy-mcp-scan.results.json")
	defer os.Remove(tempFile)

	os.Setenv("AQUA_ASSURANCE_EXPORT", tempFile)

	if err := plugin.Run(ctx, "aqua", plugin.Options{Args: args}); err != nil {
		logger.Error("Failed to run Aqua plugin", log.Err(err))
		return nil, err
	}

	sb := strings.Builder{}
	sb.WriteString("Aqua scan results:\n")
	sb.WriteString("====================================\n")
	sb.WriteString("Scan completed successfully\n")

	return mcp.NewToolResultText(sb.String()), nil

}
