package flag

import "github.com/spf13/cobra"

var (
	showVersion bool
	debug       bool
	// mcp flags
	transport       string
	port            int
	trivyBinary     string
	useAquaPlatform bool

	// login flags
	aquaKey    string
	aquaSecret string
	aquaRegion string
	clear      bool
)

func AddBaseFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "Show version")
	cmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
}

func AddMcpFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport protocol to use (sse or stdio)")
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	cmd.Flags().StringVarP(&trivyBinary, "trivy-binary", "", "", "Path to the Trivy binary")
	// TODO: Uncomment the following line when the Aqua platform is ready
	//cmd.Flags().BoolVarP(&useAquaPlatform, "use-aqua-platform", "a", false, "Use Aqua platform")
}

func AddLoginFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&aquaKey, "aqua-key", "", "Aqua key")
	cmd.Flags().StringVar(&aquaSecret, "aqua-secret", "", "Aqua secret")
	cmd.Flags().StringVar(&aquaRegion, "aqua-region", "", "Aqua region (US, EU, Singapore, Sydney, Dev)")
	cmd.Flags().BoolVar(&clear, "clear", false, "Clear the saved credentials")
}

func ToOptions() Options {
	return Options{
		Debug:       debug,
		Quiet:       false,
		ShowVersion: showVersion,

		Transport:       transport,
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
		Clear:      clear,
	}
}
