package auth

import (
	"errors"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/mark3labs/mcp-go/mcp"
)

var aquaKeyString = mcp.WithString("aquaKey",
	mcp.Required(),
	mcp.Description("The Aqua Key required to access the Aqua Platform. This MAY be available on the env as AQUA_KEY"),
)

var aquaSecretString = mcp.WithString("aquaSecret",
	mcp.Required(),
	mcp.Description("The Aqua Secret required to access the Aqua Platform. This MAY be available on the env as AQUA_SECRET"),
)

var aquaRegion = mcp.WithString("aquaRegion",
	mcp.Description("The Aqua Region to use. This MAY be available on the env as AQUA_REGION"),
	mcp.Enum("us", "eu", "sydney", "singapore", "dev"),
	mcp.DefaultString("us"),
)

func parseAquaArgs(request mcp.CallToolRequest) (*creds.AquaCreds, error) {
	aquaKey, ok := request.Params.Arguments["aquaKey"]
	if !ok {
		return nil, errors.New("aquaKey is required")
	}

	aquaSecret, ok := request.Params.Arguments["aquaSecret"]
	if !ok {
		return nil, errors.New("aquaSecret is required")
	}

	aquaRegion, ok := request.Params.Arguments["aquaRegion"]
	if !ok {
		aquaRegion = "us"
	}
	return &creds.AquaCreds{
		AquaKey:    aquaKey.(string),
		AquaSecret: aquaSecret.(string),
		Region:     aquaRegion.(string),
	}, nil
}
