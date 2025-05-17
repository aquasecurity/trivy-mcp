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
	AquaRegion   string
	AquaUsername string
	AquaPassword string
	Clear        bool
}

func (o *LoginOptions) ToAquaCreds() creds.AquaPlatformCreds {
	return creds.AquaPlatformCreds{
		AquaUsername: o.AquaUsername,
		AquaPassword: o.AquaPassword,
		Region:       o.AquaRegion,
	}
}
