package mcpserver

import (
	"context"

	"github.com/aquasecurity/trivy-plugin-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type TrivyTool struct {
	tool    mcp.Tool
	handler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
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
