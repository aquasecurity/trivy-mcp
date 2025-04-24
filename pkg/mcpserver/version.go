package mcpserver

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

var trivyVersionTool = mcp.NewTool("trivy_version",
	mcp.WithDescription("Get the version of Trivy"),
)

func (t *TrivyTools) trivyVersionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Info("Getting Trivy version...")
	return mcp.NewToolResultText("v0.61.1"), nil
}
