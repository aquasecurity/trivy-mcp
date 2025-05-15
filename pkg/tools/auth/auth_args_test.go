package auth

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
)

func TestParseAuthArgs(t *testing.T) {
	tests := []struct {
		name        string
		request     mcp.CallToolRequest
		expected    *creds.AquaCreds
		expectError bool
	}{
		{
			name: "valid args",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments,omitempty"`
					Meta      *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Name: "example",
					Arguments: map[string]any{
						"aquaKey":    "test-key",
						"aquaSecret": "test-secret",
					},
					Meta: nil,
				},
			},
			expected: &creds.AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "us",
			},
		},
		{
			name: "valid args with no region",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments,omitempty"`
					Meta      *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Name: "example",
					Arguments: map[string]any{
						"aquaKey":    "test-key",
						"aquaSecret": "test-secret",
						"aquaRegion": "us",
					},
					Meta: nil,
				},
			},
			expected: &creds.AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "us",
			},
		},
		{
			name: "args with no aquaKey",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments,omitempty"`

					Meta *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Name: "example",
					Arguments: map[string]any{
						"aquaSecret": "test-secret",
					},
					Meta: nil,
				},
			},
			expectError: true,
		},
		{
			name: "args with no aquaSecret",
			request: mcp.CallToolRequest{
				Params: struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments,omitempty"`

					Meta *struct {
						ProgressToken mcp.ProgressToken `json:"progressToken,omitempty"`
					} `json:"_meta,omitempty"`
				}{
					Name: "example",
					Arguments: map[string]any{
						"aquaKey": "test-key",
					},
					Meta: nil,
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAquaArgs(tt.request)
			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.expected.AquaKey, got.AquaKey)
			assert.Equal(t, tt.expected.AquaSecret, got.AquaSecret)
			assert.Equal(t, tt.expected.Region, got.Region)
		})
	}
}
