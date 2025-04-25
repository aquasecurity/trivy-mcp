package tools

import (
	"context"

	"github.com/aquasecurity/trivy-plugin-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type TrivyTool struct {
	Tool    mcp.Tool
	Handler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

type TrivyTools struct {
	trivyBinary string
	debug       bool
}

func NewTrivyTools(opts flag.Options) *TrivyTools {
	if opts.TrivyBinary != "" {
		log.Debug("Using Trivy binary", log.Any("trivyBinary", opts.TrivyBinary))
	}

	return &TrivyTools{
		trivyBinary: opts.TrivyBinary,
		debug:       opts.Debug,
	}
}

func (t *TrivyTools) GetTools() []TrivyTool {
	return []TrivyTool{
		{
			Tool:    scanFilesystemTool,
			Handler: t.scanWithTrivyHandler,
		},
		{
			Tool:    scanImageTool,
			Handler: t.scanWithTrivyHandler,
		},
		{
			Tool:    scanRepositoryTool,
			Handler: t.scanWithTrivyHandler,
		},
		{
			Tool:    trivyVersionTool,
			Handler: t.trivyVersionHandler,
		},
	}
}
