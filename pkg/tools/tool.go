package tools

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/internal/aqua"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/tools/aquaplatform"
	"github.com/aquasecurity/trivy-mcp/pkg/tools/scan"
	"github.com/aquasecurity/trivy-mcp/pkg/tools/version"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type TrivyTool struct {
	Tool    mcp.Tool
	Handler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

type TrivyTools struct {
	scanTools    *scan.ScanTools
	versionTools *version.VersionTools
	aquaTools    *aquaplatform.AquaPlatformTools
	trivyTempDir string
}

func NewTrivyTools(opts flag.Options, aquaClient *aqua.Client) *TrivyTools {
	if opts.TrivyBinary != "" {
		log.Debug("Using Trivy binary", log.Any("trivyBinary", opts.TrivyBinary))
	}

	trivyTempDir := filepath.Join(os.TempDir(), "trivy-mcp-cache")
	if err := os.MkdirAll(trivyTempDir, os.ModePerm); err != nil {
		log.Error("Failed to create temp dir", log.Err(err))
	}

	return &TrivyTools{
		scanTools:    scan.NewScanTools(opts, trivyTempDir),
		versionTools: version.NewVersionTools(opts, trivyTempDir),
		aquaTools:    aquaplatform.NewAquaPlatformTools(opts, trivyTempDir, aquaClient),
		trivyTempDir: filepath.Join(os.TempDir(), "trivy"),
	}
}

func (t *TrivyTools) Count() int {
	return len(t.GetTools())
}

func (t *TrivyTools) GetTools() []TrivyTool {
	return []TrivyTool{
		{
			Tool:    scan.ScanFilesystemTool,
			Handler: t.scanTools.ScanWithTrivyHandler,
		},
		{
			Tool:    scan.ScanImageTool,
			Handler: t.scanTools.ScanWithTrivyHandler,
		},
		{
			Tool:    scan.ScanRepositoryTool,
			Handler: t.scanTools.ScanWithTrivyHandler,
		},
		{
			Tool:    version.TrivyVersionTool,
			Handler: t.versionTools.TrivyVersionHandler,
		},
		{
			Tool:    aquaplatform.GetAquaSuppressionsTool,
			Handler: t.aquaTools.GetSuppressionsHandler,
		},
	}
}

func (t *TrivyTools) Cleanup() {
	if t.trivyTempDir != "" {
		log.Debug("Cleaning up temp dir", log.Any("tempDir", t.trivyTempDir))
		if err := os.RemoveAll(t.trivyTempDir); err != nil {
			log.Error("Failed to remove temp dir", log.Err(err))
		}
	}
}
