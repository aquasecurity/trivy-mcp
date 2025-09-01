package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func (t *ScanTools) processResultsFile(resultsFilePath string, scanArgs *scanArgs, filename string) (strings.Builder, error) {
	resultString := strings.Builder{}
	logger := log.WithPrefix("scan")
	if scanArgs.isSBOM {
		// tell the LLM to present the results verbatim in code block
		resultString, err := t.processSBOMResult(resultsFilePath, logger, filename)
		if err != nil {
			logger.Error("Failed to format results", log.Err(err))
			return resultString, fmt.Errorf("failed to format results: %w", err)
		}
		return resultString, nil
	}

	file, err := os.Open(resultsFilePath)
	if err != nil {
		logger.Error("Failed to open scan results file", log.Err(err))
		return resultString, errors.New("failed to open scan results file")
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close scan results file", log.Err(err))
		}
		if err := os.Remove(resultsFilePath); err != nil {
			logger.Error("Failed to remove scan results file", log.Err(err))
		}
	}()
	logger.Info("Processing scan results file", log.String("file", resultsFilePath))

	var rep types.Report
	if err := json.NewDecoder(file).Decode(&rep); err != nil {
		logger.Error("Failed to decode scan results file", log.Err(err))
		return resultString, errors.New("failed to decode scan results file")
	}

	// check the size of the file, if its larger than 1MB, we don't want to embed it in the response
	// instead we want to provide a link to the file
	fileInfo, err := file.Stat()
	if err != nil {
		logger.Error("Failed to get scan results file info", log.Err(err))
		return resultString, errors.New("failed to get scan results file info")
	}

	if fileInfo.Size() > 1024*1024 {
		resultString, err = processResultSummary(rep, logger)
		if err != nil {
			logger.Error("Failed to format results", log.Err(err))
			return resultString, fmt.Errorf("failed to format results: %w", err)
		}
	} else {
		resultString, err = processResult(rep, logger)
		if err != nil {
			logger.Error("Failed to format results", log.Err(err))
			return resultString, fmt.Errorf("failed to format results: %w", err)
		}
	}

	return resultString, nil
}

func (t *ScanTools) processAssurancePolicyResults(resultsFilePath string) (strings.Builder, error) {
	resultString := strings.Builder{}
	logger := log.WithPrefix("scan")

	log.Debug("Assurance policy results file", log.String("file", resultsFilePath))

	file, err := os.Open(resultsFilePath)
	if err != nil {
		logger.Error("Failed to open scan results file", log.Err(err))
		return resultString, errors.New("failed to open scan results file")
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close scan results file", log.Err(err))
		}
		if err := os.Remove(resultsFilePath); err != nil {
			logger.Error("Failed to remove scan results file", log.Err(err))
		}
	}()
	logger.Info("Processing scan results file", log.String("file", resultsFilePath))

	var rep AssuranceReport
	if err := json.NewDecoder(file).Decode(&rep); err != nil {
		return resultString, errors.New("failed to decode scan results file")
	}

	for _, result := range rep.Results {
		for _, pr := range result.PolicyResults {
			if pr.Failed {
				resultString.WriteString("⚠️ Assurance Policy Failed ⚠️:\n")
				resultString.WriteString("This issue MUST be resolved\n")
				resultString.WriteString(fmt.Sprintf(" - Policy Name: %s\n", pr.PolicyName))
				resultString.WriteString(fmt.Sprintf(" - Policy ID: %s\n", pr.PolicyID))
				resultString.WriteString(fmt.Sprintf(" - Reason: %s\n", pr.Reason))
				resultString.WriteString("Assurance policy failures are important and should be reported to the user\n	")
			}
		}
	}

	return resultString, nil

}

func processResultSummary(rep types.Report, logger *log.Logger) (strings.Builder, error) {
	// process the results into a text format
	sb := strings.Builder{}

	logger.Debug("Scan results file is larger than 1MB, building a summary of the results")
	countsMap := make(map[string]int)

	for _, result := range rep.Results {
		countsMap["Vulnerabilities"] += len(result.Vulnerabilities)
		countsMap["Misconfigurations"] += len(result.Misconfigurations)
		countsMap["Licenses"] += len(result.Licenses)
		countsMap["Secrets"] += len(result.Secrets)
	}

	sb.WriteString("## Scan Results Summary\n")
	sb.WriteString(fmt.Sprintf(" - Vulnerabilities: %d\n", countsMap["Vulnerabilities"]))
	sb.WriteString(fmt.Sprintf(" - Misconfigurations: %d\n", countsMap["Misconfigurations"]))
	sb.WriteString(fmt.Sprintf(" - Licenses: %d\n", countsMap["Licenses"]))
	sb.WriteString(fmt.Sprintf(" - Secrets: %d\n", countsMap["Secrets"]))
	sb.WriteString("\n\n")

	return sb, nil

}

func processResult(rep types.Report, _ *log.Logger) (strings.Builder, error) {

	// process the results into a text format
	sb := strings.Builder{}
	sb.WriteString("The scan results are below, it is important that you present the results with the severity and the ID/Name of the vulnerability/misconfiguration/license/secret. \n")

	for _, result := range rep.Results {
		if len(result.Vulnerabilities) > 0 || len(result.Misconfigurations) > 0 || len(result.Licenses) > 0 || len(result.Secrets) > 0 {
			sb.WriteString(fmt.Sprintf("## %s\n", result.Target))
			for _, vuln := range result.Vulnerabilities {
				sb.WriteString(fmt.Sprintf("### DEPENDENCY ISSUE: %s\n", vuln.VulnerabilityID))
				sb.WriteString(fmt.Sprintf(" - Severity: %s\n", vuln.Severity))
				sb.WriteString(fmt.Sprintf(" - Package: %s\n", vuln.PkgName))
				sb.WriteString(fmt.Sprintf(" - Installed Version: %s\n", vuln.InstalledVersion))
				sb.WriteString(fmt.Sprintf(" - Fixed Version: %s\n", vuln.FixedVersion))
				sb.WriteString(fmt.Sprintf(" - Primary URL: %s\n", vuln.PrimaryURL))
				sb.WriteString(fmt.Sprintf(" - Data Source: %s\n", vuln.DataSource))
			}
			for _, misconf := range result.Misconfigurations {
				sb.WriteString(fmt.Sprintf("### MISCONFIGURATION ISSUE: %s\n", misconf.ID))
				sb.WriteString(fmt.Sprintf(" - Severity: %s\n", misconf.Severity))
				sb.WriteString(fmt.Sprintf(" - Title: %s\n", misconf.Title))
				sb.WriteString(fmt.Sprintf(" - Description: %s\n", misconf.Description))
				sb.WriteString(fmt.Sprintf(" - Resolution: %s\n", misconf.Resolution))
				sb.WriteString(fmt.Sprintf(" - Primary URL: %s\n", misconf.PrimaryURL))
				sb.WriteString(fmt.Sprintf(" - Message: %s\n", misconf.Message))

			}
			for _, license := range result.Licenses {
				sb.WriteString(fmt.Sprintf("### LICENSE ISSUE: %s\n", license.Name))
				sb.WriteString(fmt.Sprintf(" - Severity: %s\n", license.Severity))
				sb.WriteString(fmt.Sprintf(" - Package: %s\n", license.PkgName))
				sb.WriteString(fmt.Sprintf(" - License: %s\n", license.Text))
				sb.WriteString(fmt.Sprintf(" - Category: %s\n", license.Category))
			}
			for _, secret := range result.Secrets {
				sb.WriteString(fmt.Sprintf("### SECRET ISSUE: %s\n", secret.RuleID))
				sb.WriteString(fmt.Sprintf(" - Severity: %s\n", secret.Severity))
				sb.WriteString(fmt.Sprintf(" - Title: %s\n", secret.Title))
				sb.WriteString(fmt.Sprintf(" - Code: %v\n", secret.Code))
				sb.WriteString(fmt.Sprintf(" - Match: %s\n", secret.Match))
				sb.WriteString(fmt.Sprintf(" - Category: %s\n", secret.Category))
			}
		}

	}
	return sb, nil
}

// processSBOMResult processes the SBOM result and returns a tool result
// we don't clean up the results file here because we want to keep it to be available for the LLM to provide a link
// when the MCP server is closed, the trivy mcp cache should be cleaned up
func (*ScanTools) processSBOMResult(resultsFilePath string, logger *log.Logger, filename string) (strings.Builder, error) {
	log.Debug("Scan results file", log.String("file", resultsFilePath))
	sb := strings.Builder{}
	// Check that the file exists
	if _, err := os.Stat(resultsFilePath); err != nil {
		logger.Error("Failed to access scan results file", log.Err(err))
		return sb, errors.New("failed to access scan results file")
	}

	// Create a markdown link for the SBOM file instead of using resource object
	// This provides better compatibility with VSCode's MCP client
	sb.WriteString(fmt.Sprintf("Only show the user the following markdown and NOTHING else \n [SBOM Results](file://%s)", resultsFilePath))

	// For large files, we return a link that client can click instead of embedding the content
	// This avoids issues with resource handling in VSCode's MCP client
	return sb, nil
}
