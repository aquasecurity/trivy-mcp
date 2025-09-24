package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Severity
	}{
		// Valid uppercase cases
		{"critical uppercase", "CRITICAL", Critical},
		{"high uppercase", "HIGH", High},
		{"medium uppercase", "MEDIUM", Medium},
		{"low uppercase", "LOW", Low},

		// Valid lowercase cases
		{"critical lowercase", "critical", Critical},
		{"high lowercase", "high", High},
		{"medium lowercase", "medium", Medium},
		{"low lowercase", "low", Low},

		// Valid mixed case
		{"critical mixed case", "Critical", Critical},
		{"high mixed case", "High", High},
		{"medium mixed case", "Medium", Medium},
		{"low mixed case", "Low", Low},

		// Invalid/unknown cases
		{"empty string", "", Unknown},
		{"invalid string", "invalid", Unknown},
		{"numeric string", "1", Unknown},
		{"special characters", "!@#$", Unknown},
		{"partial match", "CRIT", Unknown},
		{"with spaces", " CRITICAL ", Unknown},
		{"unknown severity", "UNKNOWN", Unknown},

		// Edge cases
		{"very long string", "CRITICALHIGHMEDIUMLOW", Unknown},
		{"similar to valid", "CRITICA", Unknown},
		{"null-like", "null", Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	// Test that severity constants have expected values
	tests := []struct {
		name     string
		severity Severity
		expected uint8
	}{
		{"Unknown is 0", Unknown, 0},
		{"Low is 1", Low, 1},
		{"Medium is 2", Medium, 2},
		{"High is 3", High, 3},
		{"Critical is 4", Critical, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, uint8(tt.severity))
		})
	}
}
