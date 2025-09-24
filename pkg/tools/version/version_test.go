package version

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/aquasecurity/trivy-mcp/pkg/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVersionTools(t *testing.T) {
	tests := []struct {
		name         string
		opts         flag.Options
		trivyTempDir string
	}{
		{
			name:         "default options",
			opts:         flag.Options{},
			trivyTempDir: "/tmp/test",
		},
		{
			name: "with trivy binary",
			opts: flag.Options{
				TrivyBinary: "/usr/local/bin/trivy",
				Debug:       true,
			},
			trivyTempDir: "/tmp/custom",
		},
		{
			name: "debug enabled",
			opts: flag.Options{
				Debug: true,
			},
			trivyTempDir: "/tmp/debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := NewVersionTools(tt.opts, tt.trivyTempDir)

			assert.NotNil(t, tools)
			assert.Equal(t, tt.opts.TrivyBinary, tools.trivyBinary)
			assert.Equal(t, tt.opts.Debug, tools.debug)
			// Note: trivyTempDir is hardcoded to os.TempDir() + "trivy" in the implementation
			expectedTempDir := filepath.Join(os.TempDir(), "trivy")
			assert.Equal(t, expectedTempDir, tools.trivyTempDir)
		})
	}
}

func TestTrivyVersionHandler(t *testing.T) {
	tests := []struct {
		name           string
		trivyBinary    string
		debug          bool
		expectedResult string
		expectError    bool
		setupBinary    func(t *testing.T) string // Returns path to mock binary
	}{
		{
			name:           "no trivy binary specified - use embedded version",
			trivyBinary:    "",
			debug:          false,
			expectedResult: version.TrivyVersion,
			expectError:    false,
		},
		{
			name:           "no trivy binary with debug enabled",
			trivyBinary:    "",
			debug:          true,
			expectedResult: version.TrivyVersion,
			expectError:    false,
		},
		{
			name:           "valid trivy binary",
			trivyBinary:    "", // Will be set by setupBinary
			debug:          false,
			expectedResult: "trivy version 0.48.0",
			expectError:    false,
			setupBinary: func(t *testing.T) string {
				return createMockTrivyBinary(t, "trivy version 0.48.0")
			},
		},
		{
			name:           "trivy binary with extra whitespace",
			trivyBinary:    "", // Will be set by setupBinary
			debug:          true,
			expectedResult: "trivy version 0.49.0",
			expectError:    false,
			setupBinary: func(t *testing.T) string {
				return createMockTrivyBinary(t, "  trivy version 0.49.0  \n")
			},
		},
		{
			name:        "invalid trivy binary path",
			trivyBinary: "/non/existent/trivy",
			debug:       false,
			expectError: true,
		},
		{
			name:        "trivy binary that fails",
			trivyBinary: "", // Will be set by setupBinary
			debug:       false,
			expectError: true,
			setupBinary: func(t *testing.T) string {
				return createFailingMockBinary(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trivyBinary := tt.trivyBinary
			if tt.setupBinary != nil {
				trivyBinary = tt.setupBinary(t)
			}

			opts := flag.Options{
				TrivyBinary: trivyBinary,
				Debug:       tt.debug,
			}

			tools := NewVersionTools(opts, t.TempDir())
			result, err := tools.TrivyVersionHandler(context.Background(), mcp.CallToolRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Len(t, result.Content, 1)

			textContent, ok := mcp.AsTextContent(result.Content[0])
			require.True(t, ok)
			assert.Equal(t, tt.expectedResult, textContent.Text)
		})
	}
}

func TestTrivyVersionHandler_ContextCancellation(t *testing.T) {
	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	opts := flag.Options{TrivyBinary: ""}
	tools := NewVersionTools(opts, t.TempDir())

	// Should still work since we're not using context for embedded version
	result, err := tools.TrivyVersionHandler(ctx, mcp.CallToolRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestTrivyVersionTool_Definition(t *testing.T) {
	// Test that the tool is properly defined
	assert.Equal(t, "trivy_version", TrivyVersionTool.Name)
	assert.Contains(t, TrivyVersionTool.Description, "version")
	assert.Contains(t, TrivyVersionTool.Description, "Trivy")

	// Verify it has no required parameters (it's a simple version query)
	schema := TrivyVersionTool.InputSchema
	if schema.Required != nil {
		assert.Empty(t, schema.Required, "Version tool should not require parameters")
	}
}

func TestVersionConstants(t *testing.T) {
	// Test that version constants are accessible
	assert.NotEmpty(t, version.TrivyVersion, "TrivyVersion should not be empty")
	// Note: version.TrivyVersion might be "dev" in development
}

func TestVersionTools_FieldAccess(t *testing.T) {
	// Test that we can access all fields properly
	opts := flag.Options{
		TrivyBinary: "/test/path",
		Debug:       true,
	}

	tools := NewVersionTools(opts, "/test/temp")

	// Verify fields are set correctly
	assert.Equal(t, "/test/path", tools.trivyBinary)
	assert.True(t, tools.debug)
	assert.NotEmpty(t, tools.trivyTempDir)
}

// Helper functions for creating mock binaries

func createMockTrivyBinary(t *testing.T, output string) string {
	// Create a temporary script that outputs the desired version
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "mock-trivy")

	scriptContent := `#!/bin/bash
if [ "$1" = "--version" ]; then
    echo "` + output + `"
    exit 0
else
    echo "Unknown command"
    exit 1
fi`

	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	require.NoError(t, err)

	return scriptPath
}

func createFailingMockBinary(t *testing.T) string {
	// Create a temporary script that always fails
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "failing-trivy")

	scriptContent := `#!/bin/bash
echo "Error: command failed" >&2
exit 1`

	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	require.NoError(t, err)

	return scriptPath
}

func TestTrivyVersionHandler_Integration(t *testing.T) {
	// Integration test with real trivy if available
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy binary not found in PATH, skipping integration test")
	}

	opts := flag.Options{
		TrivyBinary: trivyPath,
		Debug:       true,
	}

	tools := NewVersionTools(opts, t.TempDir())
	result, err := tools.TrivyVersionHandler(context.Background(), mcp.CallToolRequest{})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)

	textContent, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok)
	// Real trivy --version output contains "Version:" not "trivy"
	assert.Contains(t, textContent.Text, "Version:", "Real trivy output should contain 'Version:'")
	assert.NotEmpty(t, textContent.Text)
}

func TestVersionTools_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		opts    flag.Options
		tempDir string
	}{
		{
			name:    "empty temp dir",
			opts:    flag.Options{},
			tempDir: "",
		},
		{
			name: "very long binary path",
			opts: flag.Options{
				TrivyBinary: "/very/long/path/that/might/not/exist/but/should/be/handled/gracefully/trivy",
			},
			tempDir: "/tmp/test",
		},
		{
			name: "binary path with spaces",
			opts: flag.Options{
				TrivyBinary: "/path with spaces/trivy",
			},
			tempDir: "/tmp/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic during construction
			assert.NotPanics(t, func() {
				tools := NewVersionTools(tt.opts, tt.tempDir)
				assert.NotNil(t, tools)
			})
		})
	}
}
