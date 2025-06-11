package scan

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestProcessResultSummary(t *testing.T) {
	tests := []struct {
		name           string
		report         types.Report
		expectContains []string
	}{
		{
			name:           "empty report",
			report:         types.Report{},
			expectContains: []string{"Vulnerabilities: 0", "Misconfigurations: 0", "Licenses: 0", "Secrets: 0"},
		},
		{
			name: "report with findings",
			report: types.Report{
				Results: []types.Result{{
					Vulnerabilities:   []types.DetectedVulnerability{{VulnerabilityID: "CVE-1"}},
					Misconfigurations: []types.DetectedMisconfiguration{{ID: "MC-1"}},
					Licenses:          []types.DetectedLicense{{Name: "MIT"}},
					Secrets:           []types.DetectedSecret{{RuleID: "SECRET-1"}},
				}},
			},
			expectContains: []string{"Vulnerabilities: 1", "Misconfigurations: 1", "Licenses: 1", "Secrets: 1"},
		},
	}

	logger := log.WithPrefix("test")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := processResultSummary(tt.report, logger)
			assert.NoError(t, err)
			for _, want := range tt.expectContains {
				assert.Contains(t, out.String(), want)
			}
		})
	}
}
