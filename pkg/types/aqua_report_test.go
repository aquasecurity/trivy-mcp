package types

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeMap(t *testing.T) {
	tests := []struct {
		name     string
		typeID   int32
		expected string
	}{
		{"Misconfiguration type 0", 0, "Misconfiguration"},
		{"Misconfiguration type 1", 1, "Misconfiguration"},
		{"Misconfiguration type 2", 2, "Misconfiguration"},
		{"Misconfiguration type 3", 3, "Misconfiguration"},
		{"Misconfiguration type 4", 4, "Misconfiguration"},
		{"Misconfiguration type 5", 5, "Misconfiguration"},
		{"Misconfiguration type 6", 6, "Misconfiguration"},
		{"Vulnerability type 7", 7, "Vulnerability"},
		{"Secret type 8", 8, "Secret"},
		{"Misconfiguration type 9", 9, "Misconfiguration"},
		{"Pipeline type 10", 10, "Pipeline"},
		{"Sast type 11", 11, "Sast"},
		{"Misconfiguration type 12", 12, "Misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Type[tt.typeID]
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTypeMap_NonExistentKeys(t *testing.T) {
	tests := []struct {
		name   string
		typeID int32
	}{
		{"negative key", -1},
		{"large positive key", 999},
		{"unmapped key 13", 13},
		{"unmapped key 100", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Type[tt.typeID]
			assert.Equal(t, "", result, "Non-existent keys should return empty string")
		})
	}
}

func TestTypeMap_AllExpectedKeys(t *testing.T) {
	// Verify all expected keys exist
	expectedKeys := []int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	for _, key := range expectedKeys {
		t.Run(fmt.Sprintf("key_%d_exists", key), func(t *testing.T) {
			value, exists := Type[key]
			assert.True(t, exists, "Expected key %d should exist", key)
			assert.NotEmpty(t, value, "Value for key %d should not be empty", key)
		})
	}

	// Verify map size
	assert.Len(t, Type, len(expectedKeys), "Type map should have exactly %d entries", len(expectedKeys))
}

func TestAssuranceReport_BasicStructure(t *testing.T) {
	// Test that we can create and access basic fields
	var report AssuranceReport

	// Should be able to access nested fields without panicking
	assert.NotPanics(t, func() {
		report.Report.SchemaVersion = 2
		report.Report.ArtifactName = "test"
		report.Report.CreatedAt = time.Now()
	})

	// Verify values are set
	assert.Equal(t, 2, report.Report.SchemaVersion)
	assert.Equal(t, "test", report.Report.ArtifactName)
	assert.False(t, report.Report.CreatedAt.IsZero())
}

func TestAssuranceReport_JSONUnmarshaling_RealData(t *testing.T) {
	// Test with realistic JSON data that might come from Aqua Platform
	tests := []struct {
		name     string
		jsonData string
		validate func(*testing.T, AssuranceReport)
	}{
		{
			name: "minimal valid JSON",
			jsonData: `{
				"Report": {
					"SchemaVersion": 2,
					"ArtifactName": "nginx:latest",
					"ArtifactType": "container_image"
				},
				"Results": []
			}`,
			validate: func(t *testing.T, report AssuranceReport) {
				assert.Equal(t, 2, report.Report.SchemaVersion)
				assert.Equal(t, "nginx:latest", report.Report.ArtifactName)
				assert.Equal(t, "container_image", report.Report.ArtifactType)
				assert.Empty(t, report.Results)
			},
		},
		{
			name: "JSON with vulnerability result",
			jsonData: `{
				"Report": {
					"SchemaVersion": 2,
					"CreatedAt": "2023-12-01T10:00:00Z",
					"ArtifactName": "test-app",
					"Results": []
				},
				"Results": [
					{
						"AVDID": "AVD-KUB-0001",
						"Message": "Container should not run as root",
						"Type": 0,
						"Severity": 3,
						"Title": "Root User",
						"Filename": "deployment.yaml",
						"StartLine": 15,
						"EndLine": 20,
						"ExtraData": {
							"Category": "Security",
							"References": ["https://kubernetes.io/docs/concepts/security/"]
						}
					}
				]
			}`,
			validate: func(t *testing.T, report AssuranceReport) {
				assert.Equal(t, 2, report.Report.SchemaVersion)
				assert.Equal(t, "test-app", report.Report.ArtifactName)
				require.Len(t, report.Results, 1)

				result := report.Results[0]
				assert.Equal(t, "AVD-KUB-0001", result.Avdid)
				assert.Equal(t, "Container should not run as root", result.Message)
				assert.Equal(t, 0, result.Type)
				assert.Equal(t, 3, result.Severity)
				assert.Equal(t, "Root User", result.Title)
				assert.Equal(t, "deployment.yaml", result.Filename)
				assert.Equal(t, 15, result.StartLine)
				assert.Equal(t, 20, result.EndLine)
				// Note: ExtraData structure is auto-generated and complex
				// The exact structure may have multiple variants - we just verify basic access works
				assert.NotNil(t, result.ExtraData)
			},
		},
		{
			name: "JSON with multiple result types",
			jsonData: `{
				"Results": [
					{
						"AVDID": "AVD-001",
						"Type": 7,
						"Severity": 4,
						"Title": "Critical Vulnerability"
					},
					{
						"AVDID": "AVD-002", 
						"Type": 8,
						"Severity": 2,
						"Title": "Secret Found"
					},
					{
						"AVDID": "AVD-003",
						"Type": 0,
						"Severity": 1,
						"Title": "Misconfiguration"
					}
				]
			}`,
			validate: func(t *testing.T, report AssuranceReport) {
				require.Len(t, report.Results, 3)

				// Vulnerability
				assert.Equal(t, 7, report.Results[0].Type)
				assert.Equal(t, 4, report.Results[0].Severity)
				assert.Equal(t, "Critical Vulnerability", report.Results[0].Title)

				// Secret
				assert.Equal(t, 8, report.Results[1].Type)
				assert.Equal(t, 2, report.Results[1].Severity)
				assert.Equal(t, "Secret Found", report.Results[1].Title)

				// Misconfiguration
				assert.Equal(t, 0, report.Results[2].Type)
				assert.Equal(t, 1, report.Results[2].Severity)
				assert.Equal(t, "Misconfiguration", report.Results[2].Title)
			},
		},
		{
			name: "JSON with nested report results",
			jsonData: `{
				"Report": {
					"SchemaVersion": 2,
					"ArtifactName": "test-image:v1.0",
					"Results": [
						{
							"Target": "package.json",
							"Class": "lang-pkgs",
							"Type": "npm",
							"Vulnerabilities": [
								{
									"VulnerabilityID": "CVE-2023-1234",
									"PkgName": "lodash",
									"InstalledVersion": "4.17.20",
									"FixedVersion": "4.17.21",
									"Severity": "HIGH",
									"Title": "Prototype Pollution"
								}
							]
						}
					]
				}
			}`,
			validate: func(t *testing.T, report AssuranceReport) {
				assert.Equal(t, 2, report.Report.SchemaVersion)
				assert.Equal(t, "test-image:v1.0", report.Report.ArtifactName)
				require.Len(t, report.Report.Results, 1)

				result := report.Report.Results[0]
				assert.Equal(t, "package.json", result.Target)
				assert.Equal(t, "lang-pkgs", result.Class)
				assert.Equal(t, "npm", result.Type)
				require.Len(t, result.Vulnerabilities, 1)

				vuln := result.Vulnerabilities[0]
				assert.Equal(t, "CVE-2023-1234", vuln.VulnerabilityID)
				assert.Equal(t, "lodash", vuln.PkgName)
				assert.Equal(t, "4.17.20", vuln.InstalledVersion)
				assert.Equal(t, "4.17.21", vuln.FixedVersion)
				assert.Equal(t, "HIGH", vuln.Severity)
				assert.Equal(t, "Prototype Pollution", vuln.Title)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var report AssuranceReport
			err := json.Unmarshal([]byte(tt.jsonData), &report)
			require.NoError(t, err)

			tt.validate(t, report)
		})
	}
}

func TestAssuranceReport_JSONUnmarshaling_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
	}{
		{"invalid JSON", `{"Report": invalid}`},
		{"malformed JSON", `{"Report":}`},
		{"incomplete JSON", `{"Report"`},
		{"empty string", ""},
		{"truly invalid JSON", `{"invalid": json}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var report AssuranceReport
			err := json.Unmarshal([]byte(tt.jsonData), &report)
			assert.Error(t, err, "Should fail to unmarshal invalid JSON")
		})
	}
}

func TestAssuranceReport_JSONMarshaling_RoundTrip(t *testing.T) {
	// Test that we can marshal and unmarshal successfully
	tests := []struct {
		name     string
		jsonData string
	}{
		{
			name: "simple report",
			jsonData: `{
				"Report": {
					"SchemaVersion": 2,
					"ArtifactName": "test-app",
					"CreatedAt": "2023-12-01T10:00:00Z"
				},
				"Results": [
					{
						"AVDID": "TEST-001",
						"Type": 7,
						"Severity": 4,
						"Title": "Test Finding"
					}
				]
			}`,
		},
		{
			name:     "empty report",
			jsonData: `{"Report": {}, "Results": []}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unmarshal original JSON
			var original AssuranceReport
			err := json.Unmarshal([]byte(tt.jsonData), &original)
			require.NoError(t, err)

			// Marshal back to JSON
			marshaled, err := json.Marshal(original)
			require.NoError(t, err)
			assert.NotEmpty(t, marshaled)

			// Unmarshal the marshaled JSON
			var roundTrip AssuranceReport
			err = json.Unmarshal(marshaled, &roundTrip)
			require.NoError(t, err)

			// Basic validation that structure is preserved
			assert.Equal(t, original.Report.SchemaVersion, roundTrip.Report.SchemaVersion)
			assert.Equal(t, original.Report.ArtifactName, roundTrip.Report.ArtifactName)
			assert.Len(t, roundTrip.Results, len(original.Results))
		})
	}
}

func TestAssuranceReport_TypeMapIntegration(t *testing.T) {
	// Test how the Type map integrates with AssuranceReport
	jsonData := `{
		"Results": [
			{"Type": 0, "Title": "Misconfig 0"},
			{"Type": 7, "Title": "Vulnerability"},
			{"Type": 8, "Title": "Secret"},
			{"Type": 10, "Title": "Pipeline"},
			{"Type": 11, "Title": "SAST"}
		]
	}`

	var report AssuranceReport
	err := json.Unmarshal([]byte(jsonData), &report)
	require.NoError(t, err)

	// Test that Type map can be used with the results
	expectedTypes := []string{"Misconfiguration", "Vulnerability", "Secret", "Pipeline", "Sast"}

	for i, result := range report.Results {
		typeStr := Type[int32(result.Type)]
		assert.Equal(t, expectedTypes[i], typeStr, "Type mapping should work for result %d", i)
	}
}

func TestAssuranceReport_EmptyAndNilFields(t *testing.T) {
	// Test handling of empty/nil fields which are common in JSON
	jsonData := `{
		"Report": {
			"SchemaVersion": 0,
			"CreatedAt": null,
			"ArtifactName": "",
			"Results": null
		},
		"Results": null
	}`

	var report AssuranceReport
	err := json.Unmarshal([]byte(jsonData), &report)
	require.NoError(t, err)

	// Should handle empty/nil values gracefully
	assert.Equal(t, 0, report.Report.SchemaVersion)
	assert.Equal(t, "", report.Report.ArtifactName)
	assert.True(t, report.Report.CreatedAt.IsZero())
	assert.Nil(t, report.Results)
}
