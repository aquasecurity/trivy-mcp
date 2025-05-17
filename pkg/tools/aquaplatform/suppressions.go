package aquaplatform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-mcp/internal/aqua"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/mark3labs/mcp-go/mcp"
)

type AquaPlatformTools struct {
	debug           bool
	useAquaPlatform bool
	trivyTempDir    string
	aquaClient      *aqua.Client
}

func NewAquaPlatformTools(opts flag.Options, trivyTempDir string, aquaClient *aqua.Client) *AquaPlatformTools {
	return &AquaPlatformTools{
		debug:           opts.Debug,
		useAquaPlatform: opts.UseAquaPlatform,
		trivyTempDir:    trivyTempDir,
		aquaClient:      aquaClient,
	}
}

var (
	GetAquaSuppressionsTool = mcp.NewTool(
		"get_suppressions",
		mcp.WithDescription(`Gets the aqua suppressions for the connected account. The user should have already had there connectivity and access confirmed by the time this is called.`),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "Get Aqua Platform Suppressions",
		}),
	)
)

func (a *AquaPlatformTools) GetSuppressionsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if a.aquaClient == nil {
		return nil, fmt.Errorf("aqua client is not initialized so this tool cannot be used")
	}

	suppressions, err := a.aquaClient.GetSuppressions()
	if err != nil {
		return nil, err
	}

	// write the suppressions to a file using the trivy temp dir
	suppressionsFile := filepath.Join(a.trivyTempDir, "suppressions.json")
	if err := os.WriteFile(suppressionsFile, []byte(suppressions), os.ModePerm); err != nil {
		log.Error("Failed to write suppressions to file", log.Err(err))
		return nil, err
	}

	return mcp.NewToolResultResource(
		fmt.Sprintf(`The results of the call to get suppressions are in a file called "%s" found at "file://%s" \n
		You must READ the contenst of the file and parse thme to return a formated list of the suppressions. \n
		The file is accessible to you as it is on the local filesystem with correct permissions`, "suppressions.json", suppressionsFile),
		mcp.TextResourceContents{
			URI:      suppressionsFile,
			MIMEType: "application/json",
		},
	), nil
}
