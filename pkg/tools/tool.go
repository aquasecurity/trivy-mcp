package tools

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/tools/scan"
	"github.com/aquasecurity/trivy-mcp/pkg/tools/version"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type TrivyTool struct {
	Tool    mcp.Tool
	Handler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

type TrivyTools struct {
	scanTools    *scan.ScanTools
	versionTools *version.VersionTools
	trivyTempDir string
}

func NewTrivyTools(opts flag.Options) *TrivyTools {
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
		trivyTempDir: filepath.Join(os.TempDir(), "trivy"),
	}
}

func (t *TrivyTools) AddTools(s *server.MCPServer) {
	var tools []server.ServerTool

	if t.scanTools != nil {
		tools = append(tools,
			server.ServerTool{
				Tool:    scan.ScanFilesystemTool,
				Handler: t.scanTools.ScanWithTrivyHandler,
			},
			server.ServerTool{
				Tool:    scan.ScanFilesystemTool,
				Handler: t.scanTools.ScanWithTrivyHandler,
			},
			server.ServerTool{
				Tool:    scan.ScanImageTool,
				Handler: t.scanTools.ScanWithTrivyHandler,
			},
			server.ServerTool{
				Tool:    scan.ScanRepositoryTool,
				Handler: t.scanTools.ScanWithTrivyHandler,
			})
	}

	if t.versionTools != nil {
		tools = append(tools,
			server.ServerTool{
				Tool:    version.TrivyVersionTool,
				Handler: t.versionTools.TrivyVersionHandler,
			})
	}

	s.AddTools(tools...)
}

func (t *TrivyTools) Cleanup() {
	if t.trivyTempDir != "" {
		log.Info("Cleaning up mcp cache dir", log.Any("tempDir", t.trivyTempDir))
		if err := os.RemoveAll(t.trivyTempDir); err != nil {
			log.Error("Failed to remove temp dir", log.Err(err))
		}
	}
}
