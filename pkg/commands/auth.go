package commands

import (
	"fmt"
	"syscall"

	"github.com/aquasecurity/trivy-mcp/internal/aqua"
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

func getInputValue(value, title string, secret bool) (string, error) {
	if value != "" {
		return value, nil
	}
	fmt.Print(title)
	var input []byte
	var err error
	if secret {
		input, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
	} else {
		if _, err = fmt.Scanln(&input); err != nil {
			return "", err
		}
	}
	return string(input), nil
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

	existing, err := creds.LoadKeySecretCreds()
	if err != nil {
		return fmt.Errorf("failed to load existing credentials: %v", err)
	}
	if existing != nil {
		fmt.Println("Existing credentials found, are you sure you want to login again? (y/n): ")
		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
		if response != "y" && response != "Y" {
			return nil
		}
		fmt.Println("Clearing existing credentials, make sure you clear up the API Key in Aqua Platform...")
		if opts.Clear {
			if err := creds.Clear(); err != nil {
				return fmt.Errorf("failed to clear credentials: %v", err)
			}
			logger.Info("Credentials cleared successfully")
			return nil
		}

	}
	fmt.Println()
	opts.AquaUsername, err = getInputValue(opts.AquaUsername, "Enter Aqua Username: ", false)
	if err != nil {
		return err
	}
	opts.AquaPassword, err = getInputValue(opts.AquaPassword, "Enter Aqua Password: ", true)
	if err != nil {
		return err
	}
	opts.AquaRegion, err = getRegionFromList(opts.AquaRegion)
	if err != nil {
		return err
	}

	aquaClient := aqua.NewClient()
	if err := aquaClient.Login(opts.AquaUsername, opts.AquaPassword, opts.AquaRegion); err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}
	if err := aquaClient.CreateKeySecretCreds(); err != nil {
		return fmt.Errorf("failed to create key and secret credentials: %v", err)
	}

	logger.Info("Credentials saved successfully")
	return nil
}
