package mcpserver

import (
	"testing"

	"github.com/aquasecurity/trivy-mcp/pkg/flag"
	"github.com/stretchr/testify/assert"
)

func TestNewMcpServer(t *testing.T) {
	tests := []struct {
		name          string
		opts          flag.Options
		wantTransport string
		wantPort      int
	}{
		{
			name:          "default stdio",
			opts:          flag.Options{Transport: "stdio", SSEPort: 1234},
			wantTransport: "stdio",
			wantPort:      1234,
		},
		{
			name:          "sse transport",
			opts:          flag.Options{Transport: "sse", SSEPort: 5678},
			wantTransport: "sse",
			wantPort:      5678,
		},
		{
			name:          "streamable-http transport",
			opts:          flag.Options{Transport: "streamable-http", SSEPort: 9100},
			wantTransport: "streamable-http",
			wantPort:      9100,
		},
		{
			name:          "random transport",
			opts:          flag.Options{Transport: "random"},
			wantTransport: "random",
			wantPort:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewMcpServer(tt.opts)
			assert.NotNil(t, srv)
			assert.Equal(t, tt.wantTransport, srv.Transport)
			assert.Equal(t, tt.wantPort, srv.Port)
			assert.NotNil(t, srv.Server)
		})
	}
}
