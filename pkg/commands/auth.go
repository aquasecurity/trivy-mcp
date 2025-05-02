package commands

import (
	"fmt"
	"syscall"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewAuthCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Aqua Platform using AQUA Key and Secret",
		Long:  "Authenticate with Aqua Platform using AQUA Key and Secret. The credentials will be saved securely in the operating system key chain.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts := flag.ToOptions()
			// Initialize logger
			log.InitLogger(opts.Debug, opts.Quiet)
			return nil
		},
		RunE: runAuth,
	}

	flag.AddBaseFlags(cmd)
	flag.AddLoginFlags(cmd)

	return cmd
}

func getSecretValue(value, title string) (string, error) {
	if value != "" {
		return value, nil
	}
	fmt.Print(title)
	secret, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(secret), nil
}

func getRegionFromList(region string) (string, error) {
	if region != "" {
		return region, nil
	}

	availableRegions := []string{
		"US",
		"EU",
		"Singapore",
		"Sydney",
		"Dev",
	}

	fmt.Println()
	fmt.Println("Available regions:")

	for i, r := range availableRegions {
		fmt.Printf("%d. %s\n", i+1, r)
	}
	fmt.Println()
	fmt.Print("Select Aqua Region (1-5): ")
	var regionInput int
	_, err := fmt.Scanln(&regionInput)
	if err != nil {
		return "", err
	}
	if regionInput < 1 || regionInput > len(availableRegions) {
		return "", fmt.Errorf("invalid region selection: %d", regionInput)
	}

	fmt.Println()
	return availableRegions[regionInput-1], nil
}

func runAuth(cmd *cobra.Command, args []string) error {
	logger := log.WithPrefix("auth")
	opts := flag.ToLoginOptions()

	if opts.Clear {
		if err := creds.Clear(); err != nil {
			return fmt.Errorf("failed to clear credentials: %v", err)
		}
		logger.Info("Credentials cleared successfully")
		return nil
	}

	var err error
	opts.AquaKey, err = getSecretValue(opts.AquaKey, "Enter Aqua Key: ")
	if err != nil {
		return err
	}
	opts.AquaSecret, err = getSecretValue(opts.AquaSecret, "Enter Aqua Secret: ")
	if err != nil {
		return err
	}
	opts.AquaRegion, err = getRegionFromList(opts.AquaRegion)
	if err != nil {
		return err
	}

	creds := opts.ToAquaCreds()
	if err := creds.Verify(); err != nil {
		return fmt.Errorf("failed to verify credentials: %v", err)
	}

	if err := creds.Save(); err != nil {
		return fmt.Errorf("failed to save credentials: %v", err)
	}

	logger.Info("Credentials saved successfully")
	return nil
}
