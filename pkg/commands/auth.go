package commands

import (
	"fmt"
	"syscall"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

var loginCommand = &cobra.Command{
	Use:   "login",
	Short: "Login to Aqua Platform",
	Long:  "Login to Aqua Platform using AQUA Key and Secret. The credentials will be saved securely in the operating system key chain.",
	RunE:  login,
}

var logoutCommand = &cobra.Command{
	Use:   "logout",
	Short: "Logout from Aqua Platform",
	Long:  "Logout from Aqua Platform. The credentials will be removed from the operating system key chain.",
	RunE:  logout,
}

var statusCommand = &cobra.Command{
	Use:   "status",
	Short: "Check the status of Aqua Platform",
	Long:  "Check the status of Aqua Platform by verifying credentials that are presently saved.",
	RunE:  checkStatus,
}

var tokenCommand = &cobra.Command{
	Use:    "token",
	Short:  "Generate a token for Aqua Platform",
	Long:   "Generate a token for Aqua Platform using AQUA Key and Secret. The token will not be saved.",
	Hidden: true, // This command is hidden as it is not intended for public use. (it's no big issue if its used)
	RunE:   printToken,
}

func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Auth tools for the Aqua Platform",
		Long:  "Authenticate with Aqua Platform using AQUA Key and Secret. The credentials will be saved securely in the operating system key chain.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			opts := flag.ToOptions()
			log.InitLogger(opts.Debug, opts.Quiet)
		},
	}

	flag.AddBaseFlags(cmd)
	flag.AddLoginFlags(loginCommand)
	flag.AddLoginFlags(tokenCommand)

	cmd.AddCommand(loginCommand)
	cmd.AddCommand(logoutCommand)
	cmd.AddCommand(statusCommand)
	cmd.AddCommand(tokenCommand)

	return cmd
}

func login(cmd *cobra.Command, args []string) error {
	logger := log.WithPrefix("auth")
	opts := flag.ToLoginOptions()

	if opts.Clear {
		if err := creds.Clear(); err != nil {
			return fmt.Errorf("failed to clear credentials: %v", err)
		}
		logger.Info("Credentials cleared successfully")
		return nil
	}

	creds, err := getCreds(opts)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %v", err)
	}

	if err := creds.Verify(); err != nil {
		return fmt.Errorf("failed to verify credentials: %v", err)
	}

	if err := creds.Save(); err != nil {
		return fmt.Errorf("failed to save credentials: %v", err)
	}

	logger.Info("Credentials saved successfully")
	return nil
}

func logout(cmd *cobra.Command, args []string) error {
	logger := log.WithPrefix("auth")
	if err := creds.Clear(); err != nil {
		return fmt.Errorf("failed to clear credentials: %v", err)
	}
	logger.Info("Credentials cleared successfully")
	return nil
}

func printToken(cmd *cobra.Command, args []string) error {
	logger := log.WithPrefix("auth")
	opts := flag.ToLoginOptions()
	creds, err := getCreds(opts)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %v", err)
	}

	token, err := creds.GenerateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %v", err)
	}
	logger.Info("Token generated successfully")
	fmt.Println(token)
	return nil
}

func checkStatus(cmd *cobra.Command, args []string) error {
	logger := log.WithPrefix("auth")
	creds, err := creds.Load()
	if err != nil {
		if err == keyring.ErrNotFound {
			logger.Info("No credentials found")
			return nil
		}
		return fmt.Errorf("failed to load credentials: %v", err)
	}
	if err := creds.Verify(); err != nil {
		return fmt.Errorf("failed to verify credentials: %v", err)
	}
	logger.Info("Credentials verified successfully")
	return nil
}

func getCreds(opts flag.LoginOptions) (*creds.AquaCreds, error) {
	var err error
	opts.AquaKey, err = getInput(opts.AquaKey, "Enter Aqua Key: ", true)
	if err != nil {
		return nil, err
	}
	opts.AquaSecret, err = getInput(opts.AquaSecret, "Enter Aqua Secret: ", true)
	if err != nil {
		return nil, err
	}
	opts.AquaRegion, err = getRegionFromList(opts.AquaRegion)
	if err != nil {
		return nil, err
	}

	return opts.ToAquaCreds(), nil
}

func getInput(value, title string, secret bool) (string, error) {
	if value != "" {
		return value, nil
	}
	fmt.Print(title)
	var input string
	if secret {
		readIn, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil || len(readIn) == 0 {
			return "", err
		}
		input = string(readIn)
	} else {
		_, err := fmt.Scanln(&input)
		if err != nil {
			return "", err
		}
	}

	fmt.Println()
	if len(input) == 0 {
		return "", fmt.Errorf("empty input")
	}

	return string(input), nil
}

func getRegionFromList(region string) (string, error) {
	if region != "" {
		return region, nil
	}

	availableRegions := []string{"US", "EU", "Singapore", "Sydney", "Dev"}
	fmt.Println("\nAvailable regions:")

	for i, r := range availableRegions {
		fmt.Printf("%d. %s\n", i+1, r)
	}
	fmt.Print("\nSelect Aqua Region (1-5): ")
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
