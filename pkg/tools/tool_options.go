package tools

import "github.com/mark3labs/mcp-go/mcp"

// this file contains the reusable set of arguments to be used by trivy tools

var targetString = mcp.WithString("target",
	mcp.Required(),
	mcp.Description("The path to the project to scan"),
)

var scanTypeArray = mcp.WithArray("scanType",
	mcp.Required(),
	mcp.Description("The type of scan to perform"),
	mcp.Items(
		map[string]any{
			"type":        "string",
			"enum":        []string{"vuln", "misconfig", "license", "secret"},
			"description": "The type of scan to perform",
			"default":     "vuln",
		},
	),
)

var severityArray = mcp.WithArray("severities",
	mcp.Description("The severity levels to include in the scan"),
	mcp.Items(
		map[string]any{
			"type":        "string",
			"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
			"description": "The severity levels to include in the scan",
			"default":     "CRITICAL",
		},
	),
)

func targetTypeString(expectedValue string) mcp.ToolOption {
	return mcp.WithString("targetType",
		mcp.Required(),
		mcp.Description("The type of target to scan"),
		mcp.Enum(expectedValue),
		mcp.DefaultString(expectedValue),
	)
}
