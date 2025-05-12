package scan

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	resultTemplate = `{{- $totalCount := 0 -}}
{{- range . -}}
    {{- $totalCount = add $totalCount (len .Vulnerabilities) -}}
    {{- $totalCount = add $totalCount (len .Misconfigurations) -}}
    {{- $totalCount = add $totalCount (len .Licenses) -}}
    {{- $totalCount = add $totalCount (len .Secrets) -}}
{{- end -}}
{{- if eq $totalCount 0 -}}
No vulnerabilities found
{{- else -}}
Scan results:
Total vulnerabilities: {{ $totalCount }}

{{- range . }}
File: {{ .Target }}
{{- range .Vulnerabilities }}
  - ID: {{ .VulnerabilityID }}
    Severity: {{ .Severity }}
    Description: {{ .Description }}
    Package: {{ .PkgName }}
    Installed Version: {{ .InstalledVersion }}
    Fixed Version: {{ .FixedVersion }}
{{- end }}
{{- range .Misconfigurations }}
  - ID: {{ .ID }}
    Severity: {{ .Severity }}
    Description: {{ .Description }}
    Message: {{ .Message }}
    Resolution: {{ .Resolution }}
{{- end }}
{{- range .Licenses }}
  - ID: {{ .Name }}
    Severity: {{ .Severity }}
    Description: {{ .Text }}
    Confidence: {{ .Confidence }}
    Package Name: {{ .PkgName }}
    Link: {{ .Link }}
{{- end }}
{{- range .Secrets }}
  - ID: {{ .RuleID }}
    Severity: {{ .Severity }}
    Matched String: {{ .Match }}
    Message: {{ string .Category }}
    Title: {{ .Title }}
{{- end }}
{{- end }}
{{- end }}`

	summaryTemplate = `Scan results are too large to display, summarising.
{{- range . }}
File: {{ .Target }}
  - Vulnerabilities: {{ len .Vulnerabilities }}
  - Misconfigurations: {{ len .Misconfigurations }}
  - Licenses: {{ len .Licenses }}
  - Secrets: {{ len .Secrets }}
{{- end }}
Total vulnerabilities: {{ totalCount . }}`
)

// Template helper functions
var templateFuncs = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
	"totalCount": func(results []types.Result) int {
		var count int
		for _, result := range results {
			count += len(result.Vulnerabilities)
			count += len(result.Misconfigurations)
			count += len(result.Licenses)
			count += len(result.Secrets)
		}
		return count
	},
}

func executeTemplate(tmpl string, data interface{}) (string, error) {
	t, err := template.New("scan").Funcs(templateFuncs).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
