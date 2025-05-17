package mcpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy-mcp/internal/aqua"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/tools"
	"github.com/aquasecurity/trivy-mcp/pkg/version"
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
	Tools *tools.TrivyTools
	// Aqua client is the Aqua client instance
	AquaClient *aqua.Client
}

func NewMcpServer(opts flag.Options) *McpServer {
	logger := log.WithPrefix("startup")
	var aquaClient *aqua.Client
	if opts.UseAquaPlatform {
		logger.Debug("Creating an aqua client")
		aquaClient = aqua.NewClient()
		if err := aquaClient.VerifyKeySecretCreds(); err != nil {
			logger.Warn("Failed to verify aqua credentials, not using Aqua Platform")
			opts.UseAquaPlatform = false
			aquaClient.Cleanup()
			aquaClient = nil
		}
	}

	s := server.NewMCPServer(
		"Trivy MCP Server 🚀",
		version.Version,
		server.WithLogging(),
		server.WithResourceCapabilities(true, true),
	)

	th := tools.NewTrivyTools(opts, aquaClient)

	return &McpServer{
		Server:     s,
		Transport:  opts.Transport,
		Port:       opts.SSEPort,
		Tools:      th,
		AquaClient: aquaClient,
	}

}

func (m *McpServer) Start() error {
	logger := log.WithPrefix("startup")
	logger.Info("Starting Trivy MCP server", log.String("version", version.Version), log.String("transport", m.Transport), log.Int("tools", m.Tools.Count()))

	// Register the tools with the server
	for _, tool := range m.Tools.GetTools() {
		logger.Debug("Registering tool", log.String("tool", tool.Tool.Name))
		m.Server.AddTool(tool.Tool, tool.Handler)
	}

	// Start the server
	switch m.Transport {
	case "sse":
		s := server.NewSSEServer(m.Server, server.WithBaseURL(fmt.Sprintf("http://localhost:%d", m.Port)), server.WithKeepAlive(true))
		return s.Start(fmt.Sprintf(":%d", m.Port))
	case "stdio":
		s := server.NewStdioServer(m.Server)
		return s.Listen(context.Background(), os.Stdin, os.Stdout)
	default:
		return nil
	}
}

func (m *McpServer) Cleanup() {
	if m.Tools != nil {
		m.Tools.Cleanup()
	}
	if m.AquaClient != nil {
		m.AquaClient.Cleanup()
	}
}
