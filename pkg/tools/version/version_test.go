package version

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionHandler(t *testing.T) {
	tests := []struct {
		name        string
		trivyBinary string
		expected    string
	}{
		{
			name:        "Trivy Binary Not Specified",
			trivyBinary: "",
			expected:    version.TrivyVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			opts := flag.Options{
				TrivyBinary: tt.trivyBinary,
			}

			trivyTool := NewVersionTools(opts, t.TempDir())
			result, err := trivyTool.TrivyVersionHandler(context.Background(), mcp.CallToolRequest{})
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Len(t, result.Content, 1)
			require.IsType(t, mcp.TextContent{}, result.Content[0])
			assert.Equal(t, tt.expected, result.Content[0].(mcp.TextContent).Text)
		})
	}
}
