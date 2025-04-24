package commands

import (
	"context"

	"github.com/aquasecurity/trivy-plugin-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-plugin-mcp/pkg/mcpserver"
	"github.com/aquasecurity/trivy/pkg/log"
)

func Run(ctx context.Context, opts flag.Options) error {
	mcpServer := mcpserver.NewMcpServer(opts)
	if err := mcpServer.Start(); err != nil {
		log.Errorf("Failed to start MCP server: %v", err)
	}

	return nil
}
