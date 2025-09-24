package findings

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"

	aquatypes "github.com/aquasecurity/trivy-mcp/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Category uint8

const (
	CatVuln Category = iota
	CatMisconfig
	CatLicense
	CatSecret
)

func ParseCategory(s string) Category {
	switch s {
	case "vuln":
		return CatVuln
	case "misconfig":
		return CatMisconfig
	case "license":
		return CatLicense
	case "secret":
		return CatSecret
	default:
		return CatVuln
	}
}

func ParseCategories(s []any) []Category {
	categories := make([]Category, len(s))
	for i, category := range s {
		if str, ok := category.(string); ok {
			categories[i] = ParseCategory(str)
		} else {
			categories[i] = CatVuln // default or handle as needed
		}
	}
	return categories
}

type PolicyFailure struct {
	ID          string   `json:"id"`                     // deterministic ID for deduplication
	PolicyID    string   `json:"policy_id"`              // UUID from Aqua Platform
	PolicyName  string   `json:"policy_name"`            // human-readable policy name
	Reason      string   `json:"reason"`                 // failure reason
	Controls    []string `json:"controls"`               // control types that failed
	Enforced    bool     `json:"enforced"`               // whether policy is enforced
	Location    string   `json:"location"`               // file/resource location
	MatchedData string   `json:"matched_data,omitempty"` // specific data that matched
}

type Finding struct {
	ID         string   `json:"i"` // deterministic ID
	Category   Category `json:"c"` // small enum
	Severity   Severity `json:"s"`
	Identifier string   `json:"id"` // CVE-2025-XXXX, RULE-ID, etc.

	// Artifact context (kept minimal)
	ArtifactType string `json:"at,omitempty"` // "package" | "file" | "image" | "resource"
	Name         string `json:"an,omitempty"` // pkg name, resource name
	Version      string `json:"av,omitempty"` // pkg version or image tag
	Path         string `json:"ap,omitempty"` // file path / target

	// Location (optional)
	File string `json:"f,omitempty"`
	Line int    `json:"ln,omitempty"`

	// Fix info (compact)
	HasFix   bool   `json:"fx,omitempty"`
	FixedVer string `json:"fv,omitempty"`
	Cmd      string `json:"fc,omitempty"` // e.g. "npm i lodash@4.17.21"

	// Enhanced Aqua Platform fields (all omitempty)
	Title       string   `json:"title,omitempty"`
	Description string   `json:"desc,omitempty"`
	Status      string   `json:"status,omitempty"` // "fixed", etc.
	CweIDs      []string `json:"cwe,omitempty"`
	References  []string `json:"refs,omitempty"`

	// EPSS scoring
	EpssScore      *float64 `json:"epss_score,omitempty"`
	EpssPercentile *float64 `json:"epss_pct,omitempty"`
	EpssDate       string   `json:"epss_date,omitempty"`

	// CVSS data (primary/best available)
	CvssVector string   `json:"cvss_vec,omitempty"`
	CvssScore  *float64 `json:"cvss_score,omitempty"`

	// Package metadata
	Purl     string   `json:"purl,omitempty"`
	DepPath  string   `json:"dep_path,omitempty"`
	PkgRoots []string `json:"pkg_roots,omitempty"`
	Indirect *bool    `json:"indirect,omitempty"`

	// Temporal info
	PublishedDate    *time.Time `json:"pub_date,omitempty"`
	LastModifiedDate *time.Time `json:"mod_date,omitempty"`
}

func ReportToFindings(rep types.Report) ([]Finding, string /*fingerprint*/) {
	findings := []Finding{}
	for _, result := range rep.Results {
		for _, vuln := range result.Vulnerabilities {
			findings = append(findings, Finding{
				ID:           MakeFindingID(result.Target, vuln.VulnerabilityID, string(result.Type), vuln.PkgName, vuln.InstalledVersion, result.Target, 0),
				Category:     CatVuln,
				Severity:     ParseSeverity(vuln.Severity),
				Identifier:   vuln.VulnerabilityID,
				ArtifactType: string(result.Type),
				Name:         vuln.PkgName,
				Version:      vuln.InstalledVersion,
				Path:         result.Target,
				HasFix:       vuln.FixedVersion != "",
				FixedVer:     vuln.FixedVersion,
			})
		}
		for _, misconf := range result.Misconfigurations {
			findings = append(findings, Finding{
				ID:           MakeFindingID(result.Target, misconf.ID, string(result.Type), misconf.Title, "", result.Target, 0),
				Category:     CatMisconfig,
				Severity:     ParseSeverity(misconf.Severity),
				Identifier:   misconf.ID,
				ArtifactType: string(result.Type),
				Name:         misconf.Title,
				Path:         result.Target,
				HasFix:       misconf.Resolution != "",
				FixedVer:     misconf.Resolution,
			})
		}
		for _, license := range result.Licenses {
			findings = append(findings, Finding{
				ID:           MakeFindingID(result.Target, license.Name, string(result.Type), license.Name, "", result.Target, 0),
				Category:     CatLicense,
				Severity:     ParseSeverity(license.Severity),
				Identifier:   license.Name,
				ArtifactType: string(result.Type),
				Name:         license.Name,
				Path:         result.Target,
			})
		}
		for _, secret := range result.Secrets {
			findings = append(findings, Finding{
				ID:           MakeFindingID(result.Target, secret.RuleID, string(result.Type), secret.RuleID, "", result.Target, 0),
				Category:     CatSecret,
				Severity:     ParseSeverity(secret.Severity),
				Identifier:   secret.RuleID,
				ArtifactType: string(result.Type),
				Name:         secret.RuleID,
				Path:         result.Target,
			})
		}
	}
	// sort the findings to get a deterministic fingerprint
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})

	// hash the findings to get a fingerprint
	fingerprint := HashFindings(findings)
	return findings, fingerprint
}

func HashFindings(fs []Finding) string {
	h := sha1.New()
	for _, f := range fs {
		_, _ = io.WriteString(h, f.ID)
		_, _ = io.WriteString(h, "|")
		_, _ = io.WriteString(h, strconv.Itoa(int(f.Severity)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AssuranceReportToFindings converts an Aqua Platform AssuranceReport to findings and policy failures
func AssuranceReportToFindings(rep aquatypes.AssuranceReport) ([]Finding, []PolicyFailure, string /*fingerprint*/) {
	findings := []Finding{}
	policyFailures := []PolicyFailure{}

	// Process the root-level Results array which contains the actual findings
	for _, result := range rep.Results {
		// Use the Type map to convert numeric Type to artifact type
		artifactType := aquatypes.Type[int32(result.Type)]
		if artifactType == "" {
			artifactType = "unknown" // fallback for unmapped types
		}

		// Determine category based on Type mapping
		var category Category
		switch artifactType {
		case "Vulnerability":
			category = CatVuln
		case "Secret":
			category = CatSecret
		case "IaC", "Pipeline", "Sast":
			category = CatMisconfig
		default:
			category = CatMisconfig // default fallback
		}

		// Convert severity from int to string for parsing
		var severityStr string
		switch result.Severity {
		case 0:
			severityStr = "UNKNOWN"
		case 1:
			severityStr = "LOW"
		case 2:
			severityStr = "MEDIUM"
		case 3:
			severityStr = "HIGH"
		case 4:
			severityStr = "CRITICAL"
		default:
			severityStr = "UNKNOWN"
		}

		finding := Finding{
			ID:           MakeFindingID(result.Filename, result.Avdid, artifactType, result.Title, "", result.Filename, result.StartLine),
			Category:     category,
			Severity:     ParseSeverity(severityStr),
			Identifier:   result.Avdid,
			ArtifactType: artifactType,
			Name:         result.Title,
			Path:         result.Filename,
			File:         result.Filename,
			Line:         result.StartLine,

			// Enhanced Aqua Platform fields
			Title:       result.Title,
			Description: result.Message,
		}

		// Add enhanced data if available
		if result.ExtraData.References != nil {
			finding.References = result.ExtraData.References
		}
		if result.ExtraData.Cwe != "" {
			finding.CweIDs = []string{result.ExtraData.Cwe}
		}
		if result.ExtraData.Remediation != "" {
			finding.FixedVer = result.ExtraData.Remediation
			finding.HasFix = true
		}

		findings = append(findings, finding)

		// Extract policy failures from this result
		for _, policyResult := range result.PolicyResults {
			// Only process failed policies
			if !policyResult.Failed {
				continue
			}

			// Create a deterministic ID for deduplication
			policyID := MakeFindingID(result.Filename, policyResult.PolicyID, "policy", policyResult.PolicyName, "", result.Filename, result.StartLine)

			// Extract location from ControlResult if available
			location := result.Filename
			matchedData := ""
			if len(policyResult.ControlResult) > 0 {
				if policyResult.ControlResult[0].Location != "" {
					location = policyResult.ControlResult[0].Location
				}
				matchedData = policyResult.ControlResult[0].MatchedData
			}

			policyFailure := PolicyFailure{
				ID:          policyID,
				PolicyID:    policyResult.PolicyID,
				PolicyName:  policyResult.PolicyName,
				Reason:      policyResult.Reason,
				Controls:    policyResult.Controls,
				Enforced:    policyResult.Enforced,
				Location:    location,
				MatchedData: matchedData,
			}

			policyFailures = append(policyFailures, policyFailure)
		}
	}

	// sort the findings to get a deterministic fingerprint
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})

	// Sort policy failures for consistency
	sort.Slice(policyFailures, func(i, j int) bool {
		return policyFailures[i].ID < policyFailures[j].ID
	})

	// hash the findings to get a fingerprint
	fingerprint := HashFindings(findings)
	return findings, policyFailures, fingerprint
}

// GetFindingSchema returns a JSON schema describing the Finding field mappings
func GetFindingSchema() string {
	schema := map[string]string{
		"i":          "ID - Deterministic identifier for the finding",
		"c":          "Category - Type of finding (0=Vuln, 1=Misconfig, 2=License, 3=Secret)",
		"s":          "Severity - Severity level (0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical)",
		"id":         "Identifier - CVE ID, Rule ID, etc.",
		"at":         "ArtifactType - Type of artifact (package, file, image, etc.)",
		"an":         "Name - Package name, resource name, etc.",
		"av":         "Version - Package version or image tag",
		"ap":         "Path - File path or target",
		"f":          "File - Specific file path",
		"ln":         "Line - Line number in file",
		"fx":         "HasFix - Whether a fix is available",
		"fv":         "FixedVer - Fixed version or resolution",
		"fc":         "Cmd - Fix command (e.g., 'npm i lodash@4.17.21')",
		"title":      "Title - Human-readable title",
		"desc":       "Description - Detailed description",
		"status":     "Status - Status (e.g., 'fixed')",
		"cwe":        "CweIDs - Common Weakness Enumeration IDs",
		"refs":       "References - Reference URLs",
		"epss_score": "EpssScore - EPSS exploit prediction score",
		"epss_pct":   "EpssPercentile - EPSS percentile",
		"epss_date":  "EpssDate - EPSS data date",
		"cvss_vec":   "CvssVector - CVSS vector string",
		"cvss_score": "CvssScore - CVSS numerical score",
		"purl":       "Purl - Package URL",
		"dep_path":   "DepPath - Dependency path",
		"pkg_roots":  "PkgRoots - Package root dependencies",
		"indirect":   "Indirect - Whether dependency is indirect",
		"pub_date":   "PublishedDate - Vulnerability published date",
		"mod_date":   "LastModifiedDate - Last modified date",
	}

	jsonSchema, _ := json.Marshal(schema)
	return string(jsonSchema)
}

// GetPolicyFailureSchema returns a JSON schema describing the PolicyFailure field mappings
func GetPolicyFailureSchema() string {
	schema := map[string]string{
		"id":           "ID - Deterministic identifier for deduplication",
		"policy_id":    "PolicyID - UUID from Aqua Platform",
		"policy_name":  "PolicyName - Human-readable policy name",
		"reason":       "Reason - Policy failure reason",
		"controls":     "Controls - Control types that failed",
		"enforced":     "Enforced - Whether policy is enforced",
		"location":     "Location - File/resource location",
		"matched_data": "MatchedData - Specific data that matched the policy",
	}

	jsonSchema, _ := json.Marshal(schema)
	return string(jsonSchema)
}
