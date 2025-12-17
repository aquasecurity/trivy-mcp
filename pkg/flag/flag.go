package flag

import "github.com/spf13/cobra"

var (
	showVersion bool
	debug       bool
	// mcp flags
	transport       string
	host            string
	port            int
	trivyBinary     string
	useAquaPlatform bool

	// login flags
	aquaKey    string
	aquaSecret string
	aquaRegion string
)

func AddMcpFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport protocol to use (streamable-http, sse or stdio)")
	cmd.Flags().StringVarP(&host, "host", "H", "localhost", "Host/interface to listen on")
	cmd.Flags().IntVarP(&port, "port", "p", 23456, "Port to listen on")
	cmd.Flags().StringVarP(&trivyBinary, "trivy-binary", "", "", "Path to the Trivy binary")
	cmd.Flags().BoolVarP(&useAquaPlatform, "use-aqua-platform", "a", false, "Use Aqua platform")
}

func AddBaseFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "Show version")
	cmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
}

func AddLoginFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&aquaKey, "aqua-key", "", "Aqua key")
	cmd.Flags().StringVar(&aquaSecret, "aqua-secret", "", "Aqua secret")
	cmd.Flags().StringVar(&aquaRegion, "aqua-region", "", "Aqua region (US, EU, Singapore, Sydney, Dev)")
}

func ToOptions() Options {
	return Options{
		Debug:       debug,
		Quiet:       false,
		ShowVersion: showVersion,

		Transport:       transport,
		Host:            host,
		SSEPort:         port,
		TrivyBinary:     trivyBinary,
		UseAquaPlatform: useAquaPlatform,
	}
}

func ToLoginOptions() LoginOptions {
	return LoginOptions{
		AquaKey:    aquaKey,
		AquaSecret: aquaSecret,
		AquaRegion: aquaRegion,
	}
}
