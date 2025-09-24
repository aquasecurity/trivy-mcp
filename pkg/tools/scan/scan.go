package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/findings"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB, this is needed for the scan
)

type ScanTools struct {
	trivyBinary     string
	debug           bool
	useAquaPlatform bool
	trivyTempDir    string
	findingStore    *findings.Store
}

type Next struct {
	Tool    string         `json:"tool,omitempty"`    // "findings.list"
	Args    map[string]any `json:"args,omitempty"`    // pre-filled args
	Why     string         `json:"why,omitempty"`     // 1 sentence hint
	Preview []string       `json:"preview,omitempty"` // first few finding IDs
}

type ScanResponse struct {
	BatchID                      string                               `json:"batch_id"`
	Fingerprint                  string                               `json:"fingerprint"` // hash of normalized content
	Counts                       map[string]map[findings.Severity]int `json:"counts"`      // by severity/category for quick glance
	AssurancePolicyFailureCounts int                                  `json:"assurance_policy_failure_counts,omitempty"`
	Meta                         map[string]string                    `json:"meta,omitempty"`
	Next                         Next                                 `json:"next"`
}

func NewScanTools(opts flag.Options, trivyTempDir string, findingStore *findings.Store) *ScanTools {
	return &ScanTools{
		trivyBinary:     opts.TrivyBinary,
		debug:           opts.Debug,
		useAquaPlatform: opts.UseAquaPlatform,
		trivyTempDir:    trivyTempDir,
		findingStore:    findingStore,
	}
}

var (
	ScanFilesystemTool = mcp.NewTool(
		"scan_filesystem",
		mcp.WithDescription(`Scan a local filesystem project for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy. 
Follow the instructions that are given in the response.`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("filesystem"),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Scan local filesystem with Trivy",
		}),
	)

	ScanImageTool = mcp.NewTool(
		"scan_image",
		mcp.WithDescription(`Scan a container image for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy
Follow the instructions that are given in the response.`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("image"),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Scan a container image with Trivy",
		}),
	)

	ScanRepositoryTool = mcp.NewTool(
		"scan_repository",
		mcp.WithDescription(`Scan a remote git repository for vulnerabilities, misconfigurations, licenses, and secrets issue using Trivy.
Follow the instructions that are given in the response.`),
		targetString,
		scanTypeArray,
		severityArray,
		outputFormatString,
		fixedOnlyBool,
		targetTypeString("repository"),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Scan a remote git repository with Trivy",
		}),
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
	}

	if t.debug {
		args = append(args, "--debug")
	}

	// TODO: this might not be appropriate, need to check
	if scanArgs.targetType == "image" {
		args = append(args, "--skip-update")
	}

	// json output doesn't include the packages in the output
	if scanArgs.outputFormat == "json" && slices.Contains(scanArgs.scanType, "vuln") {
		args = append(args, "--list-all-pkgs")
	}

	// aquaPlatform only supports filesystem scans at the moment
	if t.useAquaPlatform && scanArgs.targetType == "filesystem" {
		aquaCreds, err := creds.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials which suggests the haven't been saved using `trivy mcp auth`: %v", err)
		}
		args = append(args, scanArgs.target)
		return t.scanWithAquaPlatform(ctx, args, *aquaCreds, scanArgs)
	}

	logger := log.WithPrefix(scanArgs.targetType)
	filename := getFilename(scanArgs.targetType, scanArgs.outputFormat)
	resultsFilePath := filepath.Join(t.trivyTempDir, filename)
	logger.Debug("Temp file for scan results", log.String("resultsFilePath", resultsFilePath))

	args = append(args, "--output", resultsFilePath)

	// finally, add the target to the arguments
	args = append(args, scanArgs.target)

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

	res, err := os.Open(resultsFilePath)
	if err != nil {
		return nil, errors.New("failed to open scan results file")
	}
	defer func() { _ = res.Close() }()

	var rep types.Report
	if err := json.NewDecoder(res).Decode(&rep); err != nil {
		return nil, errors.New("failed to decode scan results file")
	}

	fs, fp := findings.ReportToFindings(rep)

	batchID := uuid.New().String()
	t.findingStore.PutBatch(batchID, fs)

	counts := make(map[string]map[findings.Severity]int)
	for _, f := range fs {
		if _, ok := counts[f.ArtifactType]; !ok {
			counts[f.ArtifactType] = make(map[findings.Severity]int)
		}
		counts[f.ArtifactType][f.Severity]++
	}

	scanResp := ScanResponse{
		BatchID:     batchID,
		Fingerprint: fp,
		Counts:      counts,
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
