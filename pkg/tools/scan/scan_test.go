package scan

import (
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/findings"
	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/stretchr/testify/assert"
)

func TestNewScanTools(t *testing.T) {
	tests := []struct {
		name      string
		opts      flag.Options
		tmpDir    string
		wantBin   string
		wantDebug bool
		wantAqua  bool
	}{
		{
			name:      "all defaults",
			opts:      flag.Options{},
			tmpDir:    t.TempDir(),
			wantBin:   "",
			wantDebug: false,
			wantAqua:  false,
		},
		{
			name:      "custom binary and debug",
			opts:      flag.Options{TrivyBinary: "/usr/local/bin/trivy", Debug: true, UseAquaPlatform: true},
			tmpDir:    t.TempDir(),
			wantBin:   "/usr/local/bin/trivy",
			wantDebug: true,
			wantAqua:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := NewScanTools(tt.opts, tt.tmpDir, findings.NewStore())
			assert.Equal(t, tt.wantBin, st.trivyBinary)
			assert.Equal(t, tt.wantDebug, st.debug)
			assert.Equal(t, tt.wantAqua, st.useAquaPlatform)
			assert.Equal(t, tt.tmpDir, st.trivyTempDir)
		})
	}
}

func TestGetFilename(t *testing.T) {
	tests := []struct {
		name    string
		typeArg string
		format  string
		want    string
	}{
		{"json format", "filesystem", "json", "trivy-mcp-scan.filesystem-results.json"},
		{"cyclonedx format", "image", "cyclonedx", "trivy-mcp-scan.image-results.cyclonedx.json"},
		{"spdx format", "repo", "spdx", "trivy-mcp-scan.repo-results.spdx"},
		{"spdx-json format", "repo", "spdx-json", "trivy-mcp-scan.repo-results.spdx.json"},
		{"table format", "filesystem", "table", "trivy-mcp-scan.filesystem-results.table"},
		{"template format", "image", "template", "trivy-mcp-scan.image-results.template"},
		{"unknown format", "image", "unknown", "trivy-mcp-scan.image-results.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFilename(tt.typeArg, tt.format)
			assert.Equal(t, tt.want, got)
		})
	}
}
