package result

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/trivy-mcp/pkg/findings"
	"github.com/mark3labs/mcp-go/mcp"
)

var (
	avaliableScanTypes = []string{"vuln", "misconfig", "license", "secret"}
	defaultScanType    = "vuln"

	ListTool = mcp.NewTool("findings_list",
		mcp.WithDescription("List the findings from a scan"),

		mcp.WithString("batchID", mcp.Required()),
		mcp.WithString("minSeverity", mcp.Required()),
		mcp.WithArray("categories",
			mcp.Required(),
			mcp.Items(
				map[string]any{
					"type":        "string",
					"enum":        avaliableScanTypes,
					"description": "The type of scan to perform",
					"default":     defaultScanType,
				},
			)),
		mcp.WithNumber("limit", mcp.Required()),
		mcp.WithString("token", mcp.Required()),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title: "List findings from a scan that has been performed using the batchID",
		}),
	)

	GetTool = mcp.NewTool("findings_get",
		mcp.WithDescription("Get a finding from a scan"),
		mcp.WithString("batchID", mcp.Required()),
		mcp.WithString("id", mcp.Required()),
	)
)

type ResultsTools struct {
	findingStore *findings.Store
}

func NewResultsTools(findingStore *findings.Store) *ResultsTools {
	return &ResultsTools{
		findingStore: findingStore,
	}
}

func (f *ResultsTools) ListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	batchID := args["batchID"].(string)
	minSeverity := args["minSeverity"].(string)
	minSeverityVal := findings.ParseSeverity(minSeverity)
	categories := findings.ParseCategories(args["categories"].([]any))
	limit := args["limit"].(float64)
	tokenVal, ok := args["token"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'token' argument")
	}

	listResult, err := f.findingStore.List(batchID, minSeverityVal, categories, limit, tokenVal)
	if err != nil {
		return nil, err
	}

	listResult.Meta = map[string]string{
		"instruction":       "The ID should be given to the user either the CVE or the Rule ID",
		"presentation_hint": "Group findings by severity (Critical first, then High, Medium, Low)",
		"severity_colors":   `{"4":"🔴 CRITICAL","3":"🟠 HIGH","2":"🟡 MEDIUM","1":"🔵 LOW","0":"⚪ UNKNOWN"}`,
		"category_icons":    `{"0":"🛡️ Vulnerability","1":"⚙️ Misconfiguration","2":"📄 License","3":"🔑 Secret"}`,
		"action_required":   "For CRITICAL and HIGH findings, recommend immediate action",
		"url_instruction":   "Always display reference URLs when available - check 'refs' field for reference links that provide more details about the finding",
		"finding_schema":    findings.GetFindingSchema(),
	}

	if len(listResult.PolicyFailures) > 0 {
		listResult.Meta["policy_alert"] = "⚠️ POLICY VIOLATIONS DETECTED - These MUST be resolved before deployment"
		listResult.Meta["policy_priority"] = "Policy failures take precedence over regular findings"
		listResult.Meta["policy_grouping"] = "Policy failures are grouped by policy name, don't show the same policy name twice"
		listResult.Meta["policy_schema"] = findings.GetPolicyFailureSchema()
	}

	content, err := json.Marshal(listResult)
	if err != nil {
		return nil, err
	}

	return mcp.NewToolResultText(string(content)), nil
}

func (f *ResultsTools) GetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	batchID := args["batchID"].(string)
	id := args["id"].(string)

	finding, ok := f.findingStore.GetFinding(batchID, id)
	if !ok {
		return nil, fmt.Errorf("finding not found")
	}

	content, err := json.Marshal(finding)
	if err != nil {
		return nil, err
	}

	return mcp.NewToolResultText(string(content)), nil
}
