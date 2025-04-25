package mcpserver

import (
	"fmt"

	"github.com/aquasecurity/trivy-plugin-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-plugin-mcp/pkg/mcpserver/tools"
	"github.com/aquasecurity/trivy-plugin-mcp/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/server"
)

type McpServer struct {
	// Server is the MCP server instance
	Server *server.MCPServer
	// Transport is the transport protocol to use for the connection
	Transport string
	// Port is the port to listen on
	Port int
	// Tools is the list of tools to register with the server
	Tools []tools.TrivyTool
}

func NewMcpServer(opts flag.Options) *McpServer {
	s := server.NewMCPServer(
		"Trivy MCP Server 🚀",
		version.Version,
	)

	th := tools.NewTrivyTools(opts)

	return &McpServer{
		Server:    s,
		Transport: opts.Transport,
		Port:      opts.SSEPort,
		Tools:     th.GetTools(),
	}

}

func (m *McpServer) Start() error {

	// Register the tools with the server
	for _, tool := range m.Tools {
		log.Infof("Registering tool: %s", tool.Tool.Name)
		m.Server.AddTool(tool.Tool, tool.Handler)
	}

	// Start the server
	log.Infof("Starting Trivy MCP server on port :%d...", m.Port)

	if m.Transport == "sse" {
		s := server.NewSSEServer(m.Server, server.WithBaseURL(fmt.Sprintf("http://localhost:%d", m.Port)), server.WithKeepAlive(true))
		return s.Start(fmt.Sprintf(":%d", m.Port))
	} else {
		if err := server.NewStdioServer(m.Server); err == nil {
			return fmt.Errorf("failed to create Stdio server")
		}
	}
	return nil
}
