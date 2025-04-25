package mcpserver

import (
	"context"
	"fmt"
	"os"

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
		log.Info("Registering tool", log.String("tool", tool.Tool.Name))
		m.Server.AddTool(tool.Tool, tool.Handler)
	}

	// Start the server

	if m.Transport == "sse" {
		log.Info("Starting Trivy MCP server on port", log.Int("port", m.Port))
		s := server.NewSSEServer(m.Server, server.WithBaseURL(fmt.Sprintf("http://localhost:%d", m.Port)), server.WithKeepAlive(true))
		return s.Start(fmt.Sprintf(":%d", m.Port))
	} else if m.Transport == "stdio" {
		log.Info("Starting Trivy MCP server as stdio")
		s := server.NewStdioServer(m.Server)
		return s.Listen(context.Background(), os.Stdin, os.Stdout)
	}
	return nil
}
