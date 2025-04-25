package flag

import (
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
	"golang.org/x/xerrors"
)

var (
	transportFlag = trivyflag.Flag[string]{
		Name:       "transport",
		Shorthand:  "t",
		ConfigName: "mcp.transport",
		Usage:      "Transport to use for the connection",
		Default:    "sse",
		Values:     []string{"sse", "stdio"},
	}
	ssePortFlag = trivyflag.Flag[int]{
		Name:       "port",
		ConfigName: "mcp.port",
		Usage:      "sse port to use for the connection",
		Shorthand:  "p",
		Default:    23456,
	}
	trivyBinaryFlag = trivyflag.Flag[string]{
		Name:       "trivy-binary",
		ConfigName: "trivy.binary",
		Usage:      "Path to the Trivy binary",
	}
)

type McpFlagGroup struct {
	Transport   *trivyflag.Flag[string]
	SSEPort     *trivyflag.Flag[int]
	TrivyBinary *trivyflag.Flag[string]
}

type McpOptions struct {
	Transport   string
	SSEPort     int
	TrivyBinary string
}

func NewMcpFlagGroup() *McpFlagGroup {
	return &McpFlagGroup{
		Transport:   transportFlag.Clone(),
		SSEPort:     ssePortFlag.Clone(),
		TrivyBinary: trivyBinaryFlag.Clone(),
	}
}

func (f *McpFlagGroup) Name() string {
	return "MCP Server"
}

func (f *McpFlagGroup) Flags() []trivyflag.Flagger {
	return []trivyflag.Flagger{
		f.Transport,
		f.SSEPort,
		f.TrivyBinary,
	}
}

func (f *McpFlagGroup) ToOptions() (McpOptions, error) {
	if err := parseFlags(f); err != nil {
		return McpOptions{}, err
	}
	return McpOptions{
		Transport:   f.Transport.Value(),
		SSEPort:     f.SSEPort.Value(),
		TrivyBinary: f.TrivyBinary.Value(),
	}, nil
}

func parseFlags(fg trivyflag.FlagGroup) error {
	for _, flag := range fg.Flags() {
		if err := flag.Parse(); err != nil {
			return xerrors.Errorf("unable to parse flag: %w", err)
		}
	}
	return nil
}
