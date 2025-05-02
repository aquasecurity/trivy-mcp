// Package commands provides the command line interface for the trivy-mcp plugin
package commands

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/mcpserver"
	"github.com/aquasecurity/trivy-mcp/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
)

// rootCommand creates and returns a base cobra command with shared functionality
func rootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "mcp [flags]",
		Aliases: []string{},
		Args:    cobra.ExactArgs(0),
		Short:   "[EXPERIMENTAL] Start an MCP Server for Trivy",
		Long: `The MCP server is an experimental feature. 
		
It allows you to run Trivy in a server mode and connect to it using the MCP protocol.

This command starts an MCP server that listens for incoming requests and processes them using Trivy.

The server can be configured to use different transports, such as SSE (Server-Sent Events).
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts := flag.ToOptions()
			log.InitLogger(opts.Debug, opts.Quiet)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := flag.ToOptions()
			if opts.ShowVersion {
				println("Trivy MCP Version: ", version.Version)
				println("Trivy Version: ", version.TrivyVersion)
				return nil
			}

			mcpServer := mcpserver.NewMcpServer(opts)
			return mcpServer.Start()
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	return cmd
}
