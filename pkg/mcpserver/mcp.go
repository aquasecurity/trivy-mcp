package mcpserver

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
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
	// Host is the host/interface to listen on
	Host string
	// Port is the port to listen on
	Port int

	Opts flag.Options
}

func NewMcpServer(opts flag.Options) *McpServer {

	if opts.UseAquaPlatform {
		aquaCreds, err := creds.Load()
		if err != nil {
			log.Warn("Failed to load aqua credentials, not using Aqua Platform")
			opts.UseAquaPlatform = false
		} else {
			if err := aquaCreds.Verify(); err != nil {
				log.Warn("Failed to verify aqua credentials, not using Aqua Platform")
				opts.UseAquaPlatform = false
			} else {
				log.Info("Aqua credentials loaded and verified successfully")
			}
		}

	}

	s := server.NewMCPServer(
		"Trivy MCP Server 🚀",
		version.Version,
	)
	return &McpServer{
		Server:    s,
		Transport: opts.Transport,
		Host:      opts.Host,
		Port:      opts.SSEPort,
		Opts:      opts,
	}

}

func (m *McpServer) Start(ctx context.Context) error {
	th := tools.NewTrivyTools(m.Opts)
	th.AddTools(m.Server)

	var sse *server.SSEServer
	var httpServer *server.StreamableHTTPServer
	var stdio *server.StdioServer

	go func() {
		<-ctx.Done()
		log.Info("Received shutdown signal, cleaning up the mcp server...")
		if sse != nil {
			if err := sse.Shutdown(ctx); err != nil {
				log.Error("Failed to shutdown SSE server", log.Err(err))
			}
		}
		if httpServer != nil {
			if err := httpServer.Shutdown(ctx); err != nil {
				log.Error("Failed to shutdown HTTP server", log.Err(err))
			}
		}
		if th != nil {
			th.Cleanup()
		}
		os.Exit(0)
	}()

	// Start the server
	switch m.Transport {
	case "streamable-http":
		addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
		log.Info("Starting Trivy MCP server", log.String("address", addr))
		httpServer = server.NewStreamableHTTPServer(m.Server)
		return httpServer.Start(addr)
	case "sse":
		addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
		log.Info("Starting Trivy MCP server", log.String("address", addr))
		sse = server.NewSSEServer(m.Server, server.WithBaseURL(fmt.Sprintf("http://%s", addr)), server.WithKeepAlive(true))
		return sse.Start(addr)
	case "stdio":
		log.Info("Starting Trivy MCP server as stdio")
		stdio = server.NewStdioServer(m.Server)
		return stdio.Listen(context.Background(), os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unsupported transport protocol: %s", m.Transport)
	}
}
