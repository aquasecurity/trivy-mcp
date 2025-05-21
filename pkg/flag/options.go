package flag

import "github.com/aquasecurity/trivy-mcp/internal/creds"

type Options struct {
	Debug       bool
	Quiet       bool
	ShowVersion bool

	Transport       string
	SSEPort         int
	TrivyBinary     string
	UseAquaPlatform bool
}

type LoginOptions struct {
	AquaKey    string
	AquaSecret string
	AquaRegion string
	Clear      bool
}

func (o *LoginOptions) ToAquaCreds() *creds.AquaCreds {
	return &creds.AquaCreds{
		AquaKey:    o.AquaKey,
		AquaSecret: o.AquaSecret,
		Region:     o.AquaRegion,
	}
}
