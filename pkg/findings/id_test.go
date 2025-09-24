package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeFindingID(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		identifier   string
		artifactType string
		version      string
		path         string
		line         int
		want         string
	}{
		{
			name:         "valid ID",
			src:          "test",
			identifier:   "test",
			artifactType: "test",
			version:      "test",
			path:         "test",
			line:         1,
			want:         "ce722414edb6d72d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MakeFindingID(tt.src, tt.identifier, tt.artifactType, tt.name, tt.version, tt.path, tt.line)
			assert.Equal(t, tt.want, got)
		})
	}
}
