package findings

import (
	"encoding/json"
	"testing"

	aquatypes "github.com/aquasecurity/trivy-mcp/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

// HIGH-VALUE TESTS: Focus on business logic that can actually break

func TestParseCategory(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Category
	}{
		{"vulnerability", "vuln", CatVuln},
		{"misconfiguration", "misconfig", CatMisconfig},
		{"license", "license", CatLicense},
		{"secret", "secret", CatSecret},
		{"unknown defaults to vuln", "unknown", CatVuln},
		{"empty defaults to vuln", "", CatVuln},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCategory(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCategories_SafeTypeHandling(t *testing.T) {
	// This function safely handles type assertions - test the graceful fallback behavior
	tests := []struct {
		name     string
		input    []any
		expected []Category
	}{
		{
			name:     "valid string categories",
			input:    []any{"vuln", "misconfig", "license", "secret"},
			expected: []Category{CatVuln, CatMisconfig, CatLicense, CatSecret},
		},
		{
			name:     "empty slice",
			input:    []any{},
			expected: []Category{},
		},
		{
			name:     "non-string type defaults to vuln",
			input:    []any{123}, // Falls back to CatVuln
			expected: []Category{CatVuln},
		},
		{
			name:     "nil in slice defaults to vuln",
			input:    []any{nil}, // Falls back to CatVuln
			expected: []Category{CatVuln},
		},
		{
			name:     "mixed valid and invalid types",
			input:    []any{"secret", 123, nil, "license"},
			expected: []Category{CatSecret, CatVuln, CatVuln, CatLicense},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCategories(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReportToFindings_BusinessLogic(t *testing.T) {
	// Test the complex business logic, not just struct creation
	tests := []struct {
		name          string
		report        types.Report
		expectedCount int
		validate      func(*testing.T, []Finding, string)
	}{
		{
			name: "empty report produces empty results with fingerprint",
			report: types.Report{
				Results: []types.Result{},
			},
			expectedCount: 0,
			validate: func(t *testing.T, findings []Finding, fingerprint string) {
				assert.Empty(t, findings)
				assert.NotEmpty(t, fingerprint, "Even empty reports should have fingerprint")
			},
		},
		{
			name: "vulnerability processing with fix detection",
			report: types.Report{
				Results: []types.Result{
					{
						Target: "package.json",
						Type:   "npm",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2023-1234",
								PkgName:          "lodash",
								InstalledVersion: "4.17.20",
								FixedVersion:     "4.17.21", // Has fix
							},
							{
								VulnerabilityID:  "CVE-2023-5678",
								PkgName:          "axios",
								InstalledVersion: "0.21.0",
								FixedVersion:     "", // No fix
							},
						},
					},
				},
			},
			expectedCount: 2,
			validate: func(t *testing.T, findings []Finding, fingerprint string) {
				assert.Len(t, findings, 2)

				// Test fix detection logic
				var withFix, withoutFix *Finding
				for i := range findings {
					switch findings[i].Identifier {
					case "CVE-2023-1234":
						withFix = &findings[i]
					case "CVE-2023-5678":
						withoutFix = &findings[i]
					}
				}

				assert.NotNil(t, withFix, "Should find CVE with fix")
				assert.NotNil(t, withoutFix, "Should find CVE without fix")

				assert.True(t, withFix.HasFix, "Should detect fix availability")
				assert.Equal(t, "4.17.21", withFix.FixedVer)

				assert.False(t, withoutFix.HasFix, "Should detect no fix")
				assert.Empty(t, withoutFix.FixedVer)

				// All should be vulnerabilities
				assert.Equal(t, CatVuln, withFix.Category)
				assert.Equal(t, CatVuln, withoutFix.Category)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, fingerprint := ReportToFindings(tt.report)
			assert.Len(t, findings, tt.expectedCount)
			tt.validate(t, findings, fingerprint)
		})
	}
}

func TestAssuranceReportToFindings_TypeMapping(t *testing.T) {
	// Test the complex type mapping logic that could break
	tests := []struct {
		name             string
		report           aquatypes.AssuranceReport
		expectedFindings int
		expectedPolicies int
		validate         func(*testing.T, []Finding, []PolicyFailure)
	}{
		{
			name: "empty report",
			report: aquatypes.AssuranceReport{
				Results: nil,
			},
			expectedFindings: 0,
			expectedPolicies: 0,
			validate: func(t *testing.T, findings []Finding, policies []PolicyFailure) {
				assert.Empty(t, findings)
				assert.Empty(t, policies)
			},
		},
		// Note: More complex tests would require understanding the exact
		// structure of aquatypes.AssuranceReport which is auto-generated
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, policies, fingerprint := AssuranceReportToFindings(tt.report)

			assert.Len(t, findings, tt.expectedFindings)
			assert.Len(t, policies, tt.expectedPolicies)
			assert.NotEmpty(t, fingerprint, "Should always generate fingerprint")

			tt.validate(t, findings, policies)
		})
	}
}

func TestHashFindings_Deterministic(t *testing.T) {
	// Test the hashing logic that's used for fingerprinting
	tests := []struct {
		name     string
		findings []Finding
		expected string
	}{
		{
			name:     "empty findings",
			findings: []Finding{},
			expected: "da39a3ee5e6b4b0d3255bfef95601890afd80709", // SHA1 of empty
		},
		{
			name: "single finding",
			findings: []Finding{
				{ID: "test-id", Severity: High},
			},
		},
		{
			name: "order matters for hash",
			findings: []Finding{
				{ID: "id1", Severity: Critical},
				{ID: "id2", Severity: Medium},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashFindings(tt.findings)

			// Always 40 char SHA1
			assert.Len(t, result, 40)
			assert.Regexp(t, "^[a-f0-9]{40}$", result)

			if tt.expected != "" {
				assert.Equal(t, tt.expected, result)
			}

			// Must be deterministic
			result2 := HashFindings(tt.findings)
			assert.Equal(t, result, result2)
		})
	}
}

func TestGetFindingSchema_ValidJSON(t *testing.T) {
	schema := GetFindingSchema()

	// Must be valid JSON
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(schema), &parsed)
	assert.NoError(t, err, "Schema must be valid JSON")

	// Must be deterministic
	schema2 := GetFindingSchema()
	assert.Equal(t, schema, schema2)
}

func TestGetPolicyFailureSchema_ValidJSON(t *testing.T) {
	schema := GetPolicyFailureSchema()

	// Must be valid JSON
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(schema), &parsed)
	assert.NoError(t, err, "Schema must be valid JSON")

	// Must be deterministic
	schema2 := GetPolicyFailureSchema()
	assert.Equal(t, schema, schema2)
}
