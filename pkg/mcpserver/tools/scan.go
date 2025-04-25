package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/opencontainers/runtime-tools/filepath"
	"golang.org/x/xerrors"
)

var scanFilesystemTool = mcp.NewTool("scan_filesystem",
	mcp.WithDescription("Scan a project for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("The path to the project to scan"),
	),
	mcp.WithArray("scanType",
		mcp.Required(),
		mcp.Description("The type of scan to perform"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"vuln", "misconfig", "license", "secret"},
				"description": "The type of scan to perform",
				"default":     "vuln",
			},
		),
	),
	mcp.WithArray("severities",
		mcp.Description("The severity levels to include in the scan"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
				"description": "The severity levels to include in the scan",
				"default":     "CRITICAL",
			},
		),
	),
	mcp.WithString("targetType",
		mcp.Required(),
		mcp.Description("The type of target to scan"),
		mcp.Enum("filesystem"),
		mcp.DefaultString("filesystem"),
	),
)

var scanImageTool = mcp.NewTool("scan_image",
	mcp.WithDescription("Scan a container image for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("The name of the image that you want to scan"),
	),
	mcp.WithArray("scanType",
		mcp.Required(),
		mcp.Description("The type of scan to perform"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"vuln", "misconfig", "license", "secret"},
				"description": "The type of scan to perform",
				"default":     "vuln",
			},
		),
	),
	mcp.WithArray("severities",
		mcp.Description("The severity levels to include in the scan"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
				"description": "The severity levels to include in the scan",
				"default":     "CRITICAL",
			},
		),
	),
	mcp.WithString("targetType",
		mcp.Required(),
		mcp.Description("The type of target to scan"),
		mcp.Enum("filesystem", "image"),
		mcp.DefaultString("image"),
	),
)

var scanRepositoryTool = mcp.NewTool("scan_repository",
	mcp.WithDescription("Scan a remote git repository for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
	mcp.WithString("target",
		mcp.Required(),
		mcp.Description("The name of the image that you want to scan"),
	),
	mcp.WithArray("scanType",
		mcp.Required(),
		mcp.Description("The type of scan to perform"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"vuln", "misconfig", "license", "secret"},
				"description": "The type of scan to perform",
				"default":     "vuln",
			},
		),
	),
	mcp.WithArray("severities",
		mcp.Description("The severity levels to include in the scan"),
		mcp.Items(
			map[string]interface{}{
				"type":        "string",
				"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
				"description": "The severity levels to include in the scan",
				"default":     "CRITICAL",
			},
		),
	),
	mcp.WithString("targetType",
		mcp.Required(),
		mcp.Description("The type of target to scan"),
		mcp.Enum("filesystem", "image", "repository"),
		mcp.DefaultString("repository"),
	),
)

func (t *TrivyTools) scanWithTrivyHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target := request.Params.Arguments["target"].(string)
	targetType := request.Params.Arguments["targetType"].(string)

	scanType := request.Params.Arguments["scanType"].([]any)
	severities, ok := request.Params.Arguments["severities"].([]any)
	if !ok {
		severities = []any{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}

	severitiesStr := make([]string, len(severities))
	for i, severity := range severities {
		severitiesStr[i] = severity.(string)
	}

	scanTypeStr := make([]string, len(scanType))
	for i, st := range scanType {
		scanTypeStr[i] = st.(string)
	}

	logger := log.WithPrefix(targetType)
	tempFile := filepath.Join(os.TempDir(), "trivy-plugin-mcp-scan.results.json")
	args := []string{
		targetType,
		fmt.Sprintf("--scanners=%s", strings.Join(scanTypeStr, ",")),
		fmt.Sprintf("--severity=%s", strings.Join(severitiesStr, ",")),
		fmt.Sprintf("--output=%s", tempFile),
		"--format=json",
	}

	if t.debug {
		args = append(args, "--debug")
	}

	// finally, add the target
	args = append(args, target)

	logger.Debug("Trivy scan arguments", log.Any("args", args))

	if t.trivyBinary == "" {
		logger.Info("Trivy binary not set, using default path")
		app := commands.NewApp()
		app.SetArgs(args)
		if err := app.Execute(); err != nil {
			logger.Error("Failed to scan project", log.Err(err))
			return nil, errors.New("failed to scan project")
		}
	} else {
		logger.Debug("Using custom Trivy binary", log.String("binary", t.trivyBinary))
		execCmd := exec.Command(t.trivyBinary, args...)
		execCmd.Env = os.Environ()
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		if err := execCmd.Run(); err != nil {
			logger.Error("Failed to scan project", log.Err(err))
			return nil, errors.New("failed to scan project")
		}
	}

	logger.Info("Scan completed successfully")

	f, err := os.Open(tempFile)
	if err != nil {
		logger.Error("Failed to open scan results file", log.Err(err))
		return nil, errors.New("failed to open scan results file")
	}
	defer f.Close()
	defer os.Remove(tempFile)

	var r types.Report
	if err = json.NewDecoder(f).Decode(&r); err != nil {
		logger.Error("Failed to decode scan results", log.Err(err))
		return nil, xerrors.Errorf("json decode error: %w", err)
	}

	if len(r.Results) == 0 {
		logger.Info("No vulnerabilities found")
		return mcp.NewToolResultText("No vulnerabilities found"), nil
	}

	sb := strings.Builder{}
	var totalCount int

	for _, result := range r.Results {
		totalCount += len(result.Vulnerabilities) + len(result.Misconfigurations) + len(result.Licenses) + len(result.Secrets)
	}

	if totalCount == 0 {
		sb.WriteString("No vulnerabilities found\n")
		return mcp.NewToolResultText(sb.String()), nil

	}

	if totalCount > 100 {
		sb.WriteString("Scan results are too large to display, summarising.\n")
		for _, result := range r.Results {
			sb.WriteString("File: " + result.Target + "\n")
			sb.WriteString("  - Vulnerabilities: " + fmt.Sprint(len(result.Vulnerabilities)) + "\n")
			sb.WriteString("  - Misconfigurations: " + fmt.Sprint(len(result.Misconfigurations)) + "\n")
			sb.WriteString("  - Licenses: " + fmt.Sprint(len(result.Licenses)) + "\n")
			sb.WriteString("  - Secrets: " + fmt.Sprint(len(result.Secrets)) + "\n")
		}
		sb.WriteString(fmt.Sprintf("Total vulnerabilities: %d\n", totalCount))
		sb.WriteString("Please refer to the full report for more details.\n")

	} else {
		sb.WriteString("The IDs are relevant information so please include them in the output.\n")
		sb.WriteString("Scan results:\n")
		sb.WriteString(fmt.Sprintf("Total vulnerabilities: %d\n", totalCount))

		for _, result := range r.Results {
			sb.WriteString("File: " + result.Target + "\n")
			for _, vuln := range result.Vulnerabilities {
				sb.WriteString("  - ID: " + vuln.VulnerabilityID + "\n")
				sb.WriteString("    Severity: " + vuln.Severity + "\n")
				sb.WriteString("    Description: " + vuln.Description + "\n")
				sb.WriteString("    Package: " + vuln.PkgName + "\n")
				sb.WriteString("    Installed Version: " + vuln.InstalledVersion + "\n")
				sb.WriteString("    Fixed Version: " + vuln.FixedVersion + "\n")
			}
			for _, misconfig := range result.Misconfigurations {
				sb.WriteString("  - ID: " + misconfig.ID + "\n")
				sb.WriteString("    Severity: " + misconfig.Severity + "\n")
				sb.WriteString("    Description: " + misconfig.Description + "\n")
				sb.WriteString("    Message: " + misconfig.Message + "\n")
				sb.WriteString("    Resolution: " + misconfig.Resolution + "\n")
				sb.WriteString("    Status: " + string(misconfig.Status) + "\n")
			}

		}
	}

	return mcp.NewToolResultText(sb.String()), nil

}
