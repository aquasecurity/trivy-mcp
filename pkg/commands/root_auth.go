//go:build aqua
// +build aqua

package commands

import (
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/spf13/cobra"
)

// NewCmd returns the root command for trivy-mcp with Aqua platform support
func NewCmd() *cobra.Command {
	cmd := baseCommand()
	cmd.AddCommand(NewAuthCommand())
	flag.AddBaseFlags(cmd)
	flag.AddMcpFlags(cmd)
	return cmd
}
