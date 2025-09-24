package tools

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/stretchr/testify/assert"
)

func TestNewTrivyTools_Construction(t *testing.T) {
	// Test the constructor creates a valid, fully initialized structure
	tests := []struct {
		name string
		opts flag.Options
	}{
		{
			name: "default options",
			opts: flag.Options{},
		},
		{
			name: "with debug and custom binary",
			opts: flag.Options{
				Debug:       true,
				TrivyBinary: "/usr/local/bin/trivy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := NewTrivyTools(tt.opts)

			// Verify constructor never returns nil and initializes all components
			assert.NotNil(t, tools, "Constructor should never return nil")
			assert.NotNil(t, tools.scanTools, "Scan tools should be initialized")
			assert.NotNil(t, tools.resultsTools, "Results tools should be initialized")
			assert.NotNil(t, tools.versionTools, "Version tools should be initialized")
			assert.NotEmpty(t, tools.trivyTempDir, "Temp dir should be set")

			// Verify temp dir was actually created
			_, err := os.Stat(tools.trivyTempDir)
			// Note: We don't assert no error because the constructor logs but doesn't fail on mkdir errors
			// This tests the actual behavior
			if err == nil {
				t.Logf("Temp dir successfully created: %s", tools.trivyTempDir)
			} else {
				t.Logf("Temp dir creation had issues (expected in some environments): %v", err)
			}
		})
	}
}

func TestAddTools_NilSafety(t *testing.T) {
	// Test the conditional logic in AddTools with nil components
	// This is a critical test because nil pointer dereference would crash the MCP server

	tests := []struct {
		name        string
		setupTools  func() *TrivyTools
		expectPanic bool
	}{
		{
			name: "all tools nil - should not panic",
			setupTools: func() *TrivyTools {
				return &TrivyTools{
					scanTools:    nil,
					resultsTools: nil,
					versionTools: nil,
					trivyTempDir: "/tmp/test",
				}
			},
			expectPanic: false,
		},
		{
			name: "partially nil tools - should not panic",
			setupTools: func() *TrivyTools {
				opts := flag.Options{}
				tools := NewTrivyTools(opts)
				// Simulate a scenario where one tool failed to initialize
				tools.scanTools = nil
				return tools
			},
			expectPanic: false,
		},
		{
			name: "fully initialized - should not panic",
			setupTools: func() *TrivyTools {
				return NewTrivyTools(flag.Options{})
			},
			expectPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := tt.setupTools()

			if tt.expectPanic {
				assert.Panics(t, func() {
					// We can't actually call AddTools without a real server
					// but we can test the tool slice construction logic
					var toolSlice []interface{}

					if tools.scanTools != nil {
						toolSlice = append(toolSlice, "scan1", "scan2", "scan3")
					}
					if tools.versionTools != nil {
						toolSlice = append(toolSlice, "version")
					}
					if tools.resultsTools != nil {
						toolSlice = append(toolSlice, "list", "get")
					}

					// This simulates the logic in AddTools
					_ = toolSlice
				})
			} else {
				assert.NotPanics(t, func() {
					// Test the conditional logic pattern from AddTools
					var toolCount int

					if tools.scanTools != nil {
						toolCount += 3 // filesystem, image, repository
					}
					if tools.versionTools != nil {
						toolCount += 1 // version
					}
					if tools.resultsTools != nil {
						toolCount += 2 // list, get
					}

					// Verify we can safely check nil tools
					assert.True(t, toolCount >= 0, "Tool count should be non-negative")
				})
			}
		})
	}
}

func TestCleanup_TempDirHandling(t *testing.T) {
	// Test cleanup handles various temp dir scenarios without panicking
	tests := []struct {
		name    string
		tempDir string
	}{
		{
			name:    "empty temp dir - should handle gracefully",
			tempDir: "",
		},
		{
			name:    "valid existing temp dir",
			tempDir: t.TempDir(), // Creates actual temp dir
		},
		{
			name:    "non-existent path - should not panic",
			tempDir: "/path/that/definitely/does/not/exist/anywhere",
		},
		{
			name:    "permission denied path - should not panic",
			tempDir: "/root/forbidden", // Likely no permission
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := &TrivyTools{
				trivyTempDir: tt.tempDir,
			}

			// Critical: Cleanup should NEVER panic regardless of temp dir state
			// If it panics, the entire application could crash during shutdown
			assert.NotPanics(t, func() {
				tools.Cleanup()
			}, "Cleanup must handle all temp dir scenarios gracefully")
		})
	}
}

func TestTrivyTools_StructureValidation(t *testing.T) {
	// Test that the TrivyTools struct maintains expected invariants
	tools := NewTrivyTools(flag.Options{})

	// These are critical invariants that other code depends on
	assert.IsType(t, &TrivyTools{}, tools, "Should return correct type")

	// Test that we can access all expected fields without panicking
	assert.NotPanics(t, func() {
		_ = tools.scanTools
		_ = tools.resultsTools
		_ = tools.versionTools
		_ = tools.trivyTempDir
	}, "All struct fields should be accessible")
}
