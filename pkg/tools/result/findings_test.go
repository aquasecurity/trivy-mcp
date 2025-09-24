package result

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/findings"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create mock MCP requests
func createMockRequest(toolName string, args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: struct {
			Name      string    `json:"name"`
			Arguments any       `json:"arguments,omitempty"`
			Meta      *mcp.Meta `json:"_meta,omitempty"`
		}{
			Name:      toolName,
			Arguments: args,
			Meta:      nil,
		},
	}
}

// Helper function to setup a test store with sample data
func setupTestStore(t *testing.T) *findings.Store {
	store := findings.NewStoreWithSize(10)

	// Add sample findings
	testFindings := []findings.Finding{
		{
			ID:         "critical-vuln-1",
			Category:   findings.CatVuln,
			Severity:   findings.Critical,
			Identifier: "CVE-2023-1234",
			Name:       "vulnerable-package",
			Version:    "1.0.0",
		},
		{
			ID:         "high-vuln-1",
			Category:   findings.CatVuln,
			Severity:   findings.High,
			Identifier: "CVE-2023-5678",
			Name:       "another-package",
			Version:    "2.0.0",
		},
		{
			ID:         "medium-misconfig-1",
			Category:   findings.CatMisconfig,
			Severity:   findings.Medium,
			Identifier: "MISCONFIG-001",
			Name:       "config-file",
			Path:       "/etc/config.yaml",
		},
		{
			ID:         "low-license-1",
			Category:   findings.CatLicense,
			Severity:   findings.Low,
			Identifier: "LICENSE-001",
			Name:       "gpl-package",
			Version:    "3.0.0",
		},
	}

	// Add sample policy failures
	testPolicies := []findings.PolicyFailure{
		{
			ID:         "policy-fail-1",
			PolicyID:   "policy-uuid-1",
			PolicyName: "Security Policy",
			Reason:     "Unauthorized access detected",
			Enforced:   true,
			Location:   "/app/config",
		},
		{
			ID:         "policy-fail-2",
			PolicyID:   "policy-uuid-2",
			PolicyName: "Compliance Policy",
			Reason:     "Non-compliant configuration",
			Enforced:   false,
			Location:   "/etc/settings",
		},
	}

	store.PutBatchWithPolicies("test-batch", testFindings, testPolicies)
	return store
}

func TestNewResultsTools(t *testing.T) {
	store := findings.NewStore()
	tools := NewResultsTools(store)

	assert.NotNil(t, tools)
	assert.Equal(t, store, tools.findingStore)
}

func TestListHandler(t *testing.T) {
	tests := []struct {
		name             string
		batchID          string
		minSeverity      string
		categories       []any
		limit            float64
		token            string
		setupStore       func(*testing.T) *findings.Store
		expectError      bool
		expectFindings   int
		expectPolicies   int
		validateResponse func(*testing.T, *mcp.CallToolResult)
	}{
		{
			name:           "successful list with all findings",
			batchID:        "test-batch",
			minSeverity:    "LOW",
			categories:     []any{"vuln", "misconfig", "license", "secret"},
			limit:          10,
			token:          "",
			setupStore:     setupTestStore,
			expectError:    false,
			expectFindings: 4,
			expectPolicies: 2,
			validateResponse: func(t *testing.T, result *mcp.CallToolResult) {
				assert.NotNil(t, result)

				// Parse the JSON response
				var listResult findings.ListResult
				textContent, ok := mcp.AsTextContent(result.Content[0])
				require.True(t, ok)
				err := json.Unmarshal([]byte(textContent.Text), &listResult)
				require.NoError(t, err)

				// Validate metadata is present
				assert.Contains(t, listResult.Meta, "instruction")
				assert.Contains(t, listResult.Meta, "presentation_hint")
				assert.Contains(t, listResult.Meta, "severity_colors")
				assert.Contains(t, listResult.Meta, "category_icons")
				assert.Contains(t, listResult.Meta, "policy_alert")
				assert.Contains(t, listResult.Meta, "policy_priority")
			},
		},
		{
			name:           "filter by critical severity only",
			batchID:        "test-batch",
			minSeverity:    "CRITICAL",
			categories:     []any{"vuln"},
			limit:          10,
			token:          "",
			setupStore:     setupTestStore,
			expectError:    false,
			expectFindings: 1,
			expectPolicies: 2, // Policy failures are always included
		},
		{
			name:           "filter by vulnerability category only",
			batchID:        "test-batch",
			minSeverity:    "LOW",
			categories:     []any{"vuln"},
			limit:          10,
			token:          "",
			setupStore:     setupTestStore,
			expectError:    false,
			expectFindings: 2, // critical-vuln-1 and high-vuln-1
			expectPolicies: 2,
		},
		{
			name:           "limit results",
			batchID:        "test-batch",
			minSeverity:    "LOW",
			categories:     []any{"vuln", "misconfig", "license"},
			limit:          2,
			token:          "",
			setupStore:     setupTestStore,
			expectError:    false,
			expectFindings: 2, // Limited to 2
			expectPolicies: 2,
		},
		{
			name:        "non-existent batch",
			batchID:     "missing-batch",
			minSeverity: "LOW",
			categories:  []any{"vuln"},
			limit:       10,
			token:       "",
			setupStore:  setupTestStore,
			expectError: true,
		},
		{
			name:        "empty batch with no policy failures",
			batchID:     "empty-batch",
			minSeverity: "LOW",
			categories:  []any{"vuln"},
			limit:       10,
			token:       "",
			setupStore: func(t *testing.T) *findings.Store {
				store := findings.NewStoreWithSize(5)
				// Add empty batch with no policy failures
				store.PutBatch("empty-batch", []findings.Finding{})
				return store
			},
			expectError:    false,
			expectFindings: 0,
			expectPolicies: 0,
			validateResponse: func(t *testing.T, result *mcp.CallToolResult) {
				var listResult findings.ListResult
				textContent, ok := mcp.AsTextContent(result.Content[0])
				require.True(t, ok)
				err := json.Unmarshal([]byte(textContent.Text), &listResult)
				require.NoError(t, err)

				// Should NOT have policy-related metadata
				assert.NotContains(t, listResult.Meta, "policy_alert")
				assert.NotContains(t, listResult.Meta, "policy_priority")

				// But should have standard metadata
				assert.Contains(t, listResult.Meta, "instruction")
				assert.Contains(t, listResult.Meta, "presentation_hint")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupStore(t)
			tools := NewResultsTools(store)

			request := createMockRequest("findings_list", map[string]any{
				"batchID":     tt.batchID,
				"minSeverity": tt.minSeverity,
				"categories":  tt.categories,
				"limit":       tt.limit,
				"token":       tt.token,
			})

			result, err := tools.ListHandler(context.Background(), request)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Parse response to validate structure
			var listResult findings.ListResult
			textContent, ok := mcp.AsTextContent(result.Content[0])
			require.True(t, ok)
			err = json.Unmarshal([]byte(textContent.Text), &listResult)
			require.NoError(t, err)

			if tt.expectFindings >= 0 {
				assert.Len(t, listResult.Findings, tt.expectFindings)
			}
			if tt.expectPolicies >= 0 {
				assert.Len(t, listResult.PolicyFailures, tt.expectPolicies)
			}

			// Run custom validation if provided
			if tt.validateResponse != nil {
				tt.validateResponse(t, result)
			}
		})
	}
}

func TestListHandler_ArgumentValidation(t *testing.T) {
	store := setupTestStore(t)
	tools := NewResultsTools(store)

	tests := []struct {
		name        string
		args        map[string]any
		expectError bool
		errorSubstr string
	}{
		{
			name: "valid args",
			args: map[string]any{
				"batchID":     "test-batch",
				"minSeverity": "LOW",
				"categories":  []any{"vuln"},
				"limit":       10.0,
				"token":       "",
			},
			expectError: false,
		},
		// Note: The current implementation doesn't validate arguments
		// It will panic on type assertions for missing/wrong type args
		// This is a limitation of the current handler implementation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createMockRequest("findings_list", tt.args)

			result, err := tools.ListHandler(context.Background(), request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.errorSubstr != "" {
					assert.Contains(t, err.Error(), tt.errorSubstr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestGetHandler(t *testing.T) {
	tests := []struct {
		name             string
		batchID          string
		findingID        string
		setupStore       func(*testing.T) *findings.Store
		expectError      bool
		expectFindingID  string
		validateResponse func(*testing.T, *mcp.CallToolResult)
	}{
		{
			name:            "successful get existing finding",
			batchID:         "test-batch",
			findingID:       "critical-vuln-1",
			setupStore:      setupTestStore,
			expectError:     false,
			expectFindingID: "critical-vuln-1",
			validateResponse: func(t *testing.T, result *mcp.CallToolResult) {
				var finding findings.Finding
				textContent, ok := mcp.AsTextContent(result.Content[0])
				require.True(t, ok)
				err := json.Unmarshal([]byte(textContent.Text), &finding)
				require.NoError(t, err)

				assert.Equal(t, "critical-vuln-1", finding.ID)
				assert.Equal(t, findings.CatVuln, finding.Category)
				assert.Equal(t, findings.Critical, finding.Severity)
				assert.Equal(t, "CVE-2023-1234", finding.Identifier)
			},
		},
		{
			name:        "get non-existent finding",
			batchID:     "test-batch",
			findingID:   "non-existent-id",
			setupStore:  setupTestStore,
			expectError: true,
		},
		{
			name:        "get from non-existent batch",
			batchID:     "missing-batch",
			findingID:   "any-id",
			setupStore:  setupTestStore,
			expectError: true,
		},
		{
			name:        "empty finding ID",
			batchID:     "test-batch",
			findingID:   "",
			setupStore:  setupTestStore,
			expectError: true,
		},
		{
			name:        "empty batch ID",
			batchID:     "",
			findingID:   "critical-vuln-1",
			setupStore:  setupTestStore,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupStore(t)
			tools := NewResultsTools(store)

			request := createMockRequest("findings_get", map[string]any{
				"batchID": tt.batchID,
				"id":      tt.findingID,
			})

			result, err := tools.GetHandler(context.Background(), request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Validate JSON structure
			var finding findings.Finding
			textContent, ok := mcp.AsTextContent(result.Content[0])
			require.True(t, ok)
			err = json.Unmarshal([]byte(textContent.Text), &finding)
			require.NoError(t, err)

			if tt.expectFindingID != "" {
				assert.Equal(t, tt.expectFindingID, finding.ID)
			}

			// Run custom validation if provided
			if tt.validateResponse != nil {
				tt.validateResponse(t, result)
			}
		})
	}
}

func TestGetHandler_ArgumentValidation(t *testing.T) {
	store := setupTestStore(t)
	tools := NewResultsTools(store)

	tests := []struct {
		name        string
		args        map[string]any
		expectError bool
	}{
		{
			name: "valid args",
			args: map[string]any{
				"batchID": "test-batch",
				"id":      "critical-vuln-1",
			},
			expectError: false,
		},
		// Note: The current implementation doesn't validate arguments
		// It will panic on type assertions for missing/wrong type args
		// This is a limitation of the current handler implementation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createMockRequest("findings_get", tt.args)

			result, err := tools.GetHandler(context.Background(), request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestToolDefinitions(t *testing.T) {
	// Test that tool definitions are properly configured
	t.Run("ListTool configuration", func(t *testing.T) {
		assert.Equal(t, "findings_list", ListTool.Name)
		assert.Contains(t, ListTool.Description, "List the findings from a scan")

		// Verify required parameters are present
		schema := ListTool.InputSchema
		properties := schema.Properties

		assert.Contains(t, properties, "batchID")
		assert.Contains(t, properties, "minSeverity")
		assert.Contains(t, properties, "categories")
		assert.Contains(t, properties, "limit")
		assert.Contains(t, properties, "token")
	})

	t.Run("GetTool configuration", func(t *testing.T) {
		assert.Equal(t, "findings_get", GetTool.Name)
		assert.Contains(t, GetTool.Description, "Get a finding from a scan")

		// Verify required parameters are present
		schema := GetTool.InputSchema
		properties := schema.Properties

		assert.Contains(t, properties, "batchID")
		assert.Contains(t, properties, "id")
	})
}

func TestConstants(t *testing.T) {
	// Test package constants
	assert.Equal(t, []string{"vuln", "misconfig", "license", "secret"}, avaliableScanTypes)
	assert.Equal(t, "vuln", defaultScanType)
}

func TestListHandler_MetadataGeneration(t *testing.T) {
	// Test that metadata is correctly generated for different scenarios
	tests := []struct {
		name             string
		setupStore       func(*testing.T) *findings.Store
		expectPolicyMeta bool
	}{
		{
			name:             "with policy failures",
			setupStore:       setupTestStore,
			expectPolicyMeta: true,
		},
		{
			name: "without policy failures",
			setupStore: func(t *testing.T) *findings.Store {
				store := findings.NewStoreWithSize(5)
				testFindings := []findings.Finding{
					{ID: "f1", Category: findings.CatVuln, Severity: findings.High},
				}
				store.PutBatch("test-batch", testFindings)
				return store
			},
			expectPolicyMeta: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupStore(t)
			tools := NewResultsTools(store)

			request := createMockRequest("findings_list", map[string]any{
				"batchID":     "test-batch",
				"minSeverity": "LOW",
				"categories":  []any{"vuln"},
				"limit":       10.0,
				"token":       "",
			})

			result, err := tools.ListHandler(context.Background(), request)
			require.NoError(t, err)

			var listResult findings.ListResult
			textContent, ok := mcp.AsTextContent(result.Content[0])
			require.True(t, ok)
			err = json.Unmarshal([]byte(textContent.Text), &listResult)
			require.NoError(t, err)

			// Standard metadata should always be present
			assert.Contains(t, listResult.Meta, "instruction")
			assert.Contains(t, listResult.Meta, "presentation_hint")
			assert.Contains(t, listResult.Meta, "severity_colors")
			assert.Contains(t, listResult.Meta, "category_icons")
			assert.Contains(t, listResult.Meta, "action_required")
			assert.Contains(t, listResult.Meta, "url_instruction")
			assert.Contains(t, listResult.Meta, "finding_schema")

			// Policy metadata should only be present when there are policy failures
			if tt.expectPolicyMeta {
				assert.Contains(t, listResult.Meta, "policy_alert")
				assert.Contains(t, listResult.Meta, "policy_priority")
				assert.Contains(t, listResult.Meta, "policy_grouping")
				assert.Contains(t, listResult.Meta, "policy_schema")
			} else {
				assert.NotContains(t, listResult.Meta, "policy_alert")
				assert.NotContains(t, listResult.Meta, "policy_priority")
				assert.NotContains(t, listResult.Meta, "policy_grouping")
				assert.NotContains(t, listResult.Meta, "policy_schema")
			}
		})
	}
}
