package commands

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func NewCmd() *cobra.Command {

	globalFlags := trivyflag.NewGlobalFlagGroup()
	mcpFlags := &flag.Flags{
		BaseFlags: trivyflag.Flags{
			GlobalFlagGroup: globalFlags,
		},
		McpFlagGroup: flag.NewMcpFlagGroup(),
	}

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
			if err := globalFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			configPath := viper.GetString(trivyflag.ConfigFileFlag.ConfigName)
			if err := initConfig(configPath, cmd.Flags().Changed(trivyflag.ConfigFileFlag.ConfigName)); err != nil {
				return err
			}

			globalOptions, err := globalFlags.ToOptions()
			if err != nil {
				return err
			}

			// Initialize logger
			log.InitLogger(globalOptions.Debug, globalOptions.Quiet)

			if err := mcpFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := mcpFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if opts.Timeout < time.Hour {
				opts.Timeout = time.Hour
				log.Debug("Timeout is set to less than 1 hour - upgrading to 1 hour for this command.")
			}
			return Run(cmd.Context(), opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	globalFlags.AddFlags(cmd)
	mcpFlags.AddFlags(cmd)

	return cmd
}

func initConfig(configFile string, pathChanged bool) error {
	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !pathChanged {
				log.Debugf("Default config file %q not found, using built in values", log.String("file_path", configFile))
				return nil
			}
		}
		return xerrors.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Info("Loaded", log.String("file_path", configFile))
	return nil
}
