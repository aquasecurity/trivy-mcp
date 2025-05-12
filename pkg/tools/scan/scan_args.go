package scan

import (
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
)

type scanArgs struct {
	target       string
	targetType   string
	scanType     []string
	severities   []string
	outputFormat string
	isSBOM       bool
	fixedOnly    bool
}

var (
	avaliableScanTypes = []string{"vuln", "misconfig", "license", "secret"}
	defaultScanType    = "vuln"

	availableSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	defaultSeverity     = "CRITICAL"

	availableOutputFormats = []string{"json", "cyclonedx", "spdx", "spdx-json"}
	defaultOutputFormat    = "json"
)

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
			"enum":        avaliableScanTypes,
			"description": "The type of scan to perform",
			"default":     defaultScanType,
		},
	),
)

var severityArray = mcp.WithArray("severities",
	mcp.Description("The severity levels to include in the scan"),
	mcp.Items(
		map[string]any{
			"type":        "string",
			"enum":        availableSeverities,
			"description": "The severity levels to include in the scan",
			"default":     defaultSeverity,
		},
	),
)

var outputFormatString = mcp.WithString("outputFormat",
	mcp.Required(),
	mcp.Description(`The format of the output which should normally be json. \n
	When generating an SBOM report you can use either cyclonedx or spdx. For sbom, prefer cyclonedx. \n
	If the user requests spdx, use spdx rather than spdx-json.`),
	mcp.Enum(availableOutputFormats...),
	mcp.DefaultString(defaultOutputFormat),
)

var fixedOnlyBool = mcp.WithBoolean("fixedOnly",
	mcp.Description("If true, only show fixed vulnerabilities"),
	mcp.DefaultBool(false),
)

func targetTypeString(expectedValue string) mcp.ToolOption {
	return mcp.WithString("targetType",
		mcp.Required(),
		mcp.Description("The type of target to scan"),
		mcp.Enum(expectedValue),
		mcp.DefaultString(expectedValue),
	)
}

func parseScanArgs(request mcp.CallToolRequest) (*scanArgs, error) {
	target, ok := request.Params.Arguments["target"].(string)
	if !ok {
		return nil, errors.New("target is required")
	}
	targetType, ok := request.Params.Arguments["targetType"].(string)
	if !ok {
		return nil, errors.New("targetType is required")
	}
	scanType, ok := request.Params.Arguments["scanType"].([]any)
	if !ok {
		return nil, errors.New("scanType is required")
	}
	severities, ok := request.Params.Arguments["severities"].([]any)
	if !ok {
		severities = []any{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}
	severitiesStr := make([]string, len(severities))
	for i, severity := range severities {
		severitiesStr[i] = severity.(string)
	}
	scanTypeStr := make([]string, len(scanType))
	for i, st := range scanType {
		scanTypeStr[i] = st.(string)
	}
	outputFormat, ok := request.Params.Arguments["outputFormat"].(string)
	if !ok {
		outputFormat = "json"
	}
	fixedOnlyBool, ok := request.Params.Arguments["fixedOnly"].(bool)
	if !ok {
		fixedOnlyBool = false
	}

	return &scanArgs{
		target:       target,
		targetType:   targetType,
		scanType:     scanTypeStr,
		severities:   severitiesStr,
		outputFormat: outputFormat,
		isSBOM:       outputFormat == "cyclonedx" || outputFormat == "spdx" || outputFormat == "spdx-json",
		fixedOnly:    fixedOnlyBool,
	}, nil
}
