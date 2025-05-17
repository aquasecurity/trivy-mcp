package scan

import (
	"context"
	"errors"
	"fmt"
	"os"

	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/internal/aqua"
	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
)

func (t *ScanTools) scanWithAquaPlatform(ctx context.Context, args []string, aquaCreds *creds.KeySecretCreds) (*mcp.CallToolResult, error) {

	// add quiet to reduce the noise
	args = append(args, "--quiet")

	logger := log.WithPrefix("aqua")
	logger.Debug("Scanning with args", log.Any("args", args))
	logger.Info("Using Aqua platform for scanning")

	// Set the region-specific URLs
	envUrls := aqua.GetUrls(aquaCreds.Region)
	if envUrls.ApiUrl == "" || envUrls.CspmUrl == "" {
		logger.Error("Failed to get Aqua URLs")
		return nil, errors.New("failed to get Aqua URLs, the region needs to be set")
	}
	logger.Debug("Aqua URL", log.Any("AquaURL", envUrls.ApiUrl))
	logger.Debug("CSPM URL", log.Any("CSPMURL", envUrls.CspmUrl))

	// Set the Aqua credentials in the environment variables
	if err := os.Setenv("AQUA_KEY", aquaCreds.AquaKey); err != nil {
		logger.Error("Failed to set Aqua key in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("AQUA_SECRET", aquaCreds.AquaSecret); err != nil {
		logger.Error("Failed to set Aqua secret in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("CSPM_URL", envUrls.CspmUrl); err != nil {
		logger.Error("Failed to set CSPM URL in environment variables", log.Err(err))
		return nil, err
	}
	if err := os.Setenv("AQUA_URL", envUrls.ApiUrl); err != nil {
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

	resultsId := uuid.NewString()
	filename := fmt.Sprintf("%s.json", resultsId)
	resultsFilePath := filepath.Join(os.TempDir(), filename)

	if err := os.Setenv("AQUA_ASSURANCE_EXPORT", resultsFilePath); err != nil {
		logger.Error("Failed to set Aqua assurance export in environment variables", log.Err(err))
		return nil, err
	}

	if err := plugin.Run(ctx, "aqua", plugin.Options{Args: args}); err != nil {
		logger.Error("Failed to run Aqua plugin", log.Err(err))
		return nil, err
	}

	return mcp.NewToolResultResource(
		fmt.Sprintf(`The results can be found in the file "%s", which is found at "%s" \n
		 Summarise the contents of the file and report it back to the user in a nicely formatted way.\n
	It is important that the output MUST include the ID and the severity of the issues to inform the user of the issues.
	`, filename, resultsFilePath),
		mcp.TextResourceContents{
			URI:      resultsFilePath,
			MIMEType: "application/json",
		},
	), nil
}
