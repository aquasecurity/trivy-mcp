package version

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type VersionTools struct {
	trivyBinary  string
	debug        bool
	trivyTempDir string
}

func NewVersionTools(opts flag.Options, trivyTempDir string) *VersionTools {
	return &VersionTools{
		trivyBinary:  opts.TrivyBinary,
		debug:        opts.Debug,
		trivyTempDir: filepath.Join(os.TempDir(), "trivy"),
	}
}

var TrivyVersionTool = mcp.NewTool("trivy_version",
	mcp.WithDescription("Get the version of Trivy"),
)

// If the trivy binary is not specified, it will be use the version fo trivy that is baked into the binary
// at build time, the version is scraped from the go.mod, so it should be a true reflection of which trivy code version is being used
// If the trivy binary is specified, it will run the command `trivy --version` to get the version
// of the trivy binary that is being used
func (t *VersionTools) TrivyVersionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Info("Getting Trivy version...")
	ver := version.TrivyVersion

	if t.trivyBinary != "" {
		log.Debug("Using Trivy binary", log.String("trivyBinary", t.trivyBinary))
		cmd := exec.Command(t.trivyBinary, "--version")

		output, err := cmd.Output()
		if err != nil {
			log.Error("Failed to get Trivy version", log.Err(err))
			return nil, err
		}
		ver = strings.TrimSpace(string(output))
		log.Info("Trivy version", log.String("version", ver))
	}

	return mcp.NewToolResultText(ver), nil
}
