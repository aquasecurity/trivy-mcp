package tools

import (
	"context"
	"os/exec"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

var trivyVersionTool = mcp.NewTool("trivy_version",
	mcp.WithDescription("Get the version of Trivy"),
)

// trivyVersionHandler handles the request to get the version of Trivy.
// It executes the `trivy --version` command and returns the output.
// If the command fails, it returns an error.
// This is a best effort to get the version of Trivy because the calling version of Trivy might not be the same as the one that was found on the path
// this is likely a rare case, but if it presents a problem then it will need tackling.
// the option to provide a trivy binary path is available in the options struct - this will be most useful for the vscode extension when the user has
// a extension specific installation of trivy
func (t *TrivyTools) trivyVersionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Info("Getting Trivy version...")

	binaryPath, err := findTrivyBinary(t.trivyBinary)
	if err != nil {
		log.Error("Failed to find Trivy binary so can't give a definitive version number", log.Err(err))
		return nil, err
	}

	log.Debug("Using Trivy binary", log.String("trivyBinary", binaryPath))
	cmd := exec.Command(binaryPath, "--version")

	output, err := cmd.Output()
	if err != nil {
		log.Error("Failed to get Trivy version", log.Err(err))
		return nil, err
	}
	version := string(output)
	log.Info("Trivy version", log.String("version", version))

	return mcp.NewToolResultText(version), nil
}
