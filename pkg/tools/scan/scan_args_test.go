package scan

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestScanArgsCorrectlyParsed(t *testing.T) {
	tests := []struct {
		name        string
		request     mcp.CallToolRequest
		expected    *scanArgs
		expectError bool
	}{
		{
			name: "Valid Arguments",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string    `json:"name"`
					Arguments any       `json:"arguments,omitempty"`
					Meta      *mcp.Meta `json:"_meta,omitempty"`
				}{
					Name: "example",
					Arguments: map[string]any{
						"target":       "test",
						"targetType":   "filesystem",
						"scanType":     []any{"vuln"},
						"severities":   []any{"CRITICAL"},
						"outputFormat": "json",
					},
					Meta: nil,
				},
			},
			expected: &scanArgs{
				target:       "test",
				targetType:   "filesystem",
				scanType:     []string{"vuln"},
				severities:   []string{"CRITICAL"},
				outputFormat: "json",
			},
			expectError: false,
		},
		{
			name: "Repository scan with branch",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string    `json:"name"`
					Arguments any       `json:"arguments,omitempty"`
					Meta      *mcp.Meta `json:"_meta,omitempty"`
				}{
					Name: "scan_repository",
					Arguments: map[string]any{
						"target":       "https://github.com/acme/infra",
						"targetType":   "repository",
						"scanType":     []any{"vuln", "misconfig", "secret"},
						"severities":   []any{"MEDIUM"},
						"outputFormat": "json",
						"branch":       "feature/add-vm",
					},
					Meta: nil,
				},
			},
			expected: &scanArgs{
				target:       "https://github.com/acme/infra",
				targetType:   "repository",
				scanType:     []string{"vuln", "misconfig", "secret"},
				severities:   []string{"MEDIUM"},
				outputFormat: "json",
				branch:       "feature/add-vm",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseScanArgs(tt.request)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
