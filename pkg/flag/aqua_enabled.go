//go:build aqua
// +build aqua

package flag

import "github.com/spf13/cobra"

func AddMcpFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport protocol to use (sse or stdio)")
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	cmd.Flags().StringVarP(&trivyBinary, "trivy-binary", "", "", "Path to the Trivy binary")
	cmd.Flags().BoolVarP(&useAquaPlatform, "use-aqua-platform", "a", false, "Use Aqua platform")
}
