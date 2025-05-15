package auth

import (
	"context"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type AuthTools struct {
	trivyBinary     string
	debug           bool
	useAquaPlatform bool
}

func NewAuthTools(opts flag.Options) *AuthTools {
	return &AuthTools{
		trivyBinary:     opts.TrivyBinary,
		debug:           opts.Debug,
		useAquaPlatform: opts.UseAquaPlatform,
	}
}

var (
	AuthLoginTool = mcp.NewTool(
		"aqua_login",
		mcp.WithDescription(`Login to Aqua Plaform by setting the credential. \n
         You will need to ask for the credentials that aren't available. \n`),
		aquaKeyString,
		aquaSecretString,
		aquaRegion,
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Provide Aqua credentials to access the Aqua Platform",
		}),
	)

	AuthLogoutTool = mcp.NewTool(
		"aqua_logout",
		mcp.WithDescription("Logout from Aqua using the provided credentials. Some of the credentials may be available on the env but some may need to be asked for."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Logout from Aqua",
		}),
	)
)

func (a *AuthTools) AuthLoginHandler(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logger := log.WithPrefix("auth")

	creds, err := parseAquaArgs(request)
	if err != nil {
		return mcp.NewToolResultText("Could not parse the credentials so they will need to be provided by asking the user. We need the aquaKey, aquaSecret and the region"), nil
	}

	if creds.AquaKey == "" || creds.AquaSecret == "" {
		return mcp.NewToolResultText("Aqua credentials are not set. Need to get them manually from the user"), nil
	}

	if err := creds.Verify(); err != nil {
		logger.Error("Failed to verify the credentials", log.Err(err))
		return mcp.NewToolResultText("Aqua credentials are not valid. Need to get them manually from the user"), nil
	}

	if err := creds.Save(); err != nil {
		return mcp.NewToolResultText("Failed to save the credentials. Need to get them manually from the user"), nil
	}
	return mcp.NewToolResultText("Aqua credentials are valid and saved successfully"), nil
}

func (a *AuthTools) AuthLogoutHandler(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := creds.Clear(); err != nil {
		return mcp.NewToolResultText("Failed to clear the credentials. Need to get them manually from the user"), nil
	}
	return mcp.NewToolResultText("Aqua credentials are cleared successfully"), nil
}
