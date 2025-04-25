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

var (
	scanFilesystemTool = mcp.NewTool(
		"scan_filesystem",
		mcp.WithDescription("Scan a project for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
		targetString,
		scanTypeArray,
		severityArray,
		targetTypeString("filesystem"),
	)

	scanImageTool = mcp.NewTool(
		"scan_image",
		mcp.WithDescription("Scan a container image for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
		targetString,
		scanTypeArray,
		severityArray,
		targetTypeString("image"),
	)

	scanRepositoryTool = mcp.NewTool(
		"scan_repository",
		mcp.WithDescription("Scan a remote git repository for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy"),
		targetString,
		scanTypeArray,
		severityArray,
		targetTypeString("repository"),
	)
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

	// finally, add the target to the arguments
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

	sb := strings.Builder{}
	var totalCount int

	for _, result := range r.Results {
		totalCount += len(result.Vulnerabilities) + len(result.Misconfigurations) + len(result.Licenses) + len(result.Secrets)
	}

	if totalCount == 0 {
		sb.WriteString("No vulnerabilities found\n")
		return mcp.NewToolResultText(sb.String()), nil

	}

	// Check if the total count of vulnerabilities is greater than 100 - this is a
	// fairly arbitrary number, but it is a good starting point for limiting the output
	// to a manageable size. The LLM can only handle a limited amount of data, so we need to summarise the results
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
	} else {
		sb.WriteString("The ID and Severity are relevant information so please include them in the output.\n")
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
			}
			for _, license := range result.Licenses {
				sb.WriteString("  - ID: " + license.Name + "\n")
				sb.WriteString("    Severity: " + license.Severity + "\n")
				sb.WriteString("    Description: " + license.Text + "\n")
				sb.WriteString("    Confidence: " + fmt.Sprint(license.Confidence) + "\n")
				sb.WriteString("	Package Name: " + license.PkgName + "\n")
				sb.WriteString("    Link: " + license.Link + "\n")
			}
			for _, secret := range result.Secrets {
				sb.WriteString("  - ID: " + secret.RuleID + "\n")
				sb.WriteString("    Severity: " + secret.Severity + "\n")
				sb.WriteString("    Matched String: " + secret.Match + "\n")
				sb.WriteString("    Message: " + string(secret.Category) + "\n")
				sb.WriteString("    Title: " + secret.Title + "\n")
			}
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}
