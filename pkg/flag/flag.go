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
	aquaUsername string
	aquaPassword string
	aquaRegion   string
	clear        bool
)

func AddBaseFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "Show version")
	cmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
}

func AddLoginFlags(cmd *cobra.Command) {
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
		AquaRegion:   aquaRegion,
		AquaUsername: aquaUsername,
		AquaPassword: aquaPassword,
		Clear:        clear,
	}
}
