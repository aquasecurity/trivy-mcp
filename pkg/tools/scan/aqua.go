package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/findings"
	aquatypes "github.com/aquasecurity/trivy-mcp/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
)

func (t *ScanTools) scanWithAquaPlatform(ctx context.Context, args []string, creds creds.AquaCreds, scanArgs *scanArgs) (*mcp.CallToolResult, error) {

	// add quiet to reduce the noise
	args = append(args, "--quiet")

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

	assuranceFilename := "trivy-mcp-scan.assurance.json"
	assuranceResultFilePath := filepath.Join(os.TempDir(), assuranceFilename)

	var envMap = map[string]string{
		"AQUA_KEY":                     creds.AquaKey,
		"AQUA_SECRET":                  creds.AquaSecret,
		"CSPM_URL":                     cspmURL,
		"AQUA_URL":                     aquaURL,
		"AQUA_ASSURANCE_EXPORT":        assuranceResultFilePath,
		"TRIVY_SKIP_REPOSITORY_UPLOAD": "true",
		"TRIVY_SKIP_RESULT_UPLOAD":     "true",
		"TRIVY_IDE_IDENTIFIER":         "mcp",
		"GRADLE":                       "1",
		"DOTNET_PROJ":                  "1",
		"SAST":                         "1",
	}

	for key, value := range envMap {
		if err := os.Setenv(key, value); err != nil {
			logger.Error("Failed to set environment variable", log.String("key", key), log.String("value", value), log.Err(err))
			return nil, err
		}
	}

	defer func() {
		for key := range envMap {
			if err := os.Unsetenv(key); err != nil {
				logger.Error("Failed to unset environment variable", log.String("key", key), log.Err(err))
			}
		}
	}()

	logger.Debug("Environment", log.Any("ENV", os.Environ()))

	filename := "trivy-mcp-scan.results.json"
	resultsFilePath := filepath.Join(os.TempDir(), filename)
	args = append(args, "--output", resultsFilePath)

	// error code 13 means the assurance policy failed
	if err := plugin.Run(ctx, "aqua", plugin.Options{Args: args}); err != nil && !strings.Contains(err.Error(), "exit status 13") {
		logger.Error("Failed to run Aqua plugin", log.Err(err))
	}

	res, err := os.Open(assuranceResultFilePath)
	if err != nil {
		return nil, errors.New("failed to open scan results file")
	}
	defer func() { _ = res.Close() }()

	var rep aquatypes.AssuranceReport
	if err := json.NewDecoder(res).Decode(&rep); err != nil {
		return nil, errors.New("failed to decode scan results file")
	}

	fs, policyFailures, fp := findings.AssuranceReportToFindings(rep)

	batchID := uuid.New().String()
	t.findingStore.PutBatch(batchID, fs)
	t.findingStore.PutBatchWithPolicies(batchID, fs, policyFailures)

	counts := make(map[string]map[findings.Severity]int)
	for _, f := range fs {
		if _, ok := counts[f.ArtifactType]; !ok {
			counts[f.ArtifactType] = make(map[findings.Severity]int)
		}
		counts[f.ArtifactType][f.Severity]++
	}

	scanResp := ScanResponse{
		BatchID:                      batchID,
		Fingerprint:                  fp,
		Counts:                       counts,
		AssurancePolicyFailureCounts: len(policyFailures),
		Meta: map[string]string{
			"target":       scanArgs.target,
			"targetType":   scanArgs.targetType,
			"scanType":     strings.Join(scanArgs.scanType, ","),
			"severities":   strings.Join(scanArgs.severities, ","),
			"outputFormat": scanArgs.outputFormat,
			"fixedOnly":    fmt.Sprintf("%t", scanArgs.fixedOnly),
		},
		Next: Next{
			Tool: "findings_list",
			Why:  "To see the list of findings",
		},
	}

	scanRespJSON, err := json.Marshal(scanResp)
	if err != nil {
		return nil, errors.New("failed to marshal scan response")
	}

	return mcp.NewToolResultText(string(scanRespJSON)), nil
}
