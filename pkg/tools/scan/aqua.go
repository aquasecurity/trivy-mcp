package scan

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

func (t *ScanTools) scanWithAquaPlatform(ctx context.Context, args []string, creds creds.AquaCreds) (*mcp.CallToolResult, error) {

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
	if err := os.Setenv("AQUA_KEY", creds.AquaKey); err != nil {
		logger.Error("Failed to set Aqua key in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("AQUA_SECRET", creds.AquaSecret); err != nil {
		logger.Error("Failed to set Aqua secret in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("CSPM_URL", cspmURL); err != nil {
		logger.Error("Failed to set CSPM URL in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("AQUA_URL", aquaURL); err != nil {
		logger.Error("Failed to set Aqua URL in environment variables", log.Err(err))
		return nil, err
	}

	defer func() {
		// clear the environment variables after the scan
		// This is important to avoid leaking credentials
		if err := os.Unsetenv("AQUA_KEY"); err != nil {
			logger.Error("Failed to unset Aqua key in environment variables", log.Err(err))
		}
		if err := os.Unsetenv("AQUA_SECRET"); err != nil {
			logger.Error("Failed to unset Aqua secret in environment variables", log.Err(err))
		}
		if err := os.Unsetenv("CSPM_URL"); err != nil {
			logger.Error("Failed to unset CSPM URL in environment variables", log.Err(err))
		}
		if err := os.Unsetenv("AQUA_URL"); err != nil {
			logger.Error("Failed to unset Aqua URL in environment variables", log.Err(err))
		}
	}()

	logger.Debug("Environment", log.Any("ENV", os.Environ()))

	tempFile := filepath.Join(os.TempDir(), "trivy-mcp-scan.results.json")
	defer func() {
		if err := os.Remove(tempFile); err != nil {
			logger.Error("Failed to remove temp file", log.Err(err))
		}
	}()

	if err := os.Setenv("AQUA_ASSURANCE_EXPORT", tempFile); err != nil {
		logger.Error("Failed to set Aqua assurance export in environment variables", log.Err(err))
		return nil, err
	}

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
