package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

type ScanTools struct {
	trivyBinary     string
	debug           bool
	useAquaPlatform bool
	trivyTempDir    string
}

func NewScanTools(opts flag.Options, trivyTempDir string) *ScanTools {
	return &ScanTools{
		trivyBinary:     opts.TrivyBinary,
		debug:           opts.Debug,
		useAquaPlatform: opts.UseAquaPlatform,
		trivyTempDir:    trivyTempDir,
	}
}

var (
	ScanFilesystemTool = mcp.NewTool(
		"scan_filesystem",
		mcp.WithDescription(`Scan a local filesystem project for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy. \n
		When the result is an embedded resource (like an SBOM), you MUST format the response as a clickable markdown link with the text set to "SBOM Results" and with the URI as the target of the link. \n
		Do not include any other text or explanation with the link.".`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("filesystem"),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Scan filesystem and local projects with Trivy",
		}),
	)

	ScanImageTool = mcp.NewTool(
		"scan_image",
		mcp.WithDescription(`Scan a container image for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy \n
		When the result is an embedded resource (like an SBOM), you MUST format the response as a clickable markdown link with the text set to the filename and the URI as the target of the link. \n
		Do not include any other text or explanation with the link.".`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("image"),
	)

	ScanRepositoryTool = mcp.NewTool(
		"scan_repository",
		mcp.WithDescription(`Scan a remote git repository for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy \n
		When the result is an embedded resource (like an SBOM), you MUST format the response as a clickable markdown link with the text set to "SBOM Results" and with the URI as the target of the link. \n
		Do not include any other text or explanation with the link.".`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("repository"),
	)
)

func (t *ScanTools) ScanWithTrivyHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	scanArgs, err := parseScanArgs(request)
	if err != nil {
		return nil, err
	}

	args := []string{
		scanArgs.targetType,
		fmt.Sprintf("--scanners=%s", strings.Join(scanArgs.scanType, ",")),
		fmt.Sprintf("--severity=%s", strings.Join(scanArgs.severities, ",")),
		fmt.Sprintf("--format=%s", scanArgs.outputFormat),
		"--quiet",
	}

	if t.debug {
		args = append(args, "--debug")
	}

	// TODO: this might not be appropriate, need to check
	if scanArgs.targetType == "image" {
		args = append(args, "--skip-update")
	}

	// json output doesn't include the target in the output
	if scanArgs.outputFormat == "json" && slices.Contains(scanArgs.scanType, "vuln") {
		args = append(args, "--list-all-pkgs")
	}

	// aquaPlatform only supports filesystem scans at the moment
	if t.useAquaPlatform && scanArgs.targetType == "filesystem" {
		aquaCreds, err := creds.LoadKeySecretCreds()
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials which suggests the haven't been saved using `trivy mcp auth`: %v", err)
		}
		args = append(args, scanArgs.target)
		return t.scanWithAquaPlatform(ctx, args, aquaCreds)
	}

	logger := log.WithPrefix(scanArgs.targetType)
	filename := getFilename(scanArgs.targetType, scanArgs.outputFormat)
	resultsFilePath := filepath.Join(t.trivyTempDir, filename)
	logger.Debug("Temp file for scan results", log.String("resultsFilePath", resultsFilePath))

	args = append(args, "--output", resultsFilePath)

	// finally, add the target to the arguments
	args = append(args, scanArgs.target)

	logger.Debug("Trivy scan arguments", log.Any("args", args))

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open os.DevNull", log.Err(err))
		return nil, errors.New("failed to open os.DevNull")
	}
	defer func() { _ = devNull.Close() }()

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

		execCmd.Stdout = devNull
		execCmd.Stderr = devNull
		if err := execCmd.Run(); err != nil {
			logger.Error("Failed to scan project", log.Err(err))
			return nil, errors.New("failed to scan project")
		}
	}

	logger.Info("Scan completed successfully")

	if scanArgs.isSBOM {
		// tell the LLM to present the results verbatim in code block
		result, err := t.processSBOMResult(resultsFilePath, logger, filename)
		if err != nil {
			logger.Error("Failed to format results", log.Err(err))
			return nil, fmt.Errorf("failed to format results: %w", err)
		}
		return result, nil
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

// processSBOMResult processes the SBOM result and returns a tool result
// we don't clean up the results file here because we want to keep it to be available for the LLM to provide a link
// when the MCP server is closed, the trivy mcp cache should be cleaned up
func (*ScanTools) processSBOMResult(resultsFilePath string, logger *log.Logger, filename string) (*mcp.CallToolResult, error) {
	log.Debug("Scan results file", log.String("file", resultsFilePath))

	content, err := os.ReadFile(resultsFilePath)
	if err != nil {
		logger.Error("Failed to read scan results file", log.Err(err))
		return nil, errors.New("failed to read scan results file")
	}

	return mcp.NewToolResultResource(
		fmt.Sprintf("The embedded resource is a human readable SBOM format. "+
"The filename is %s and the URI is file://%s.", filename, resultsFilePath),
		mcp.TextResourceContents{
			URI:  resultsFilePath,
			Text: string(content),
		},
	), nil
}

func getFilename(targetType, format string) string {
	switch format {
	case "json":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.json", targetType)
	case "cyclonedx":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.cyclonedx.json", targetType)
	case "spdx":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.spdx", targetType)
	case "spdx-json":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.spdx.json", targetType)
	case "table":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.table", targetType)
	case "template":
		return fmt.Sprintf("trivy-mcp-scan.%s-results.template", targetType)
	default:
		return fmt.Sprintf("trivy-mcp-scan.%s-results.json", targetType)
	}
}
