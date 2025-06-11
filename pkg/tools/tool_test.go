package tools

import (
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/stretchr/testify/assert"
)

func TestNewTrivyTools(t *testing.T) {
	tests := []struct {
		name string
		opts flag.Options
	}{
		{"default opts", flag.Options{}},
		{"with debug", flag.Options{Debug: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewTrivyTools(tt.opts)
			assert.NotNil(t, tr)
		})
	}
}

func TestTrivyTools_Cleanup(t *testing.T) {
	tr := NewTrivyTools(flag.Options{})
	// The Cleanup method should not panic
	assert.NotPanics(t, func() {
		tr.Cleanup()
	})
}
