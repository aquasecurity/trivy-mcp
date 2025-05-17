package aqua

import "strings"

type EnvUrls struct {
	CspmUrl string
	UILogin string
	ApiUrl  string
}

func GetUrls(region string) EnvUrls {
	switch strings.ToLower(region) {
	case "dev":
		return EnvUrls{
			CspmUrl: "https://stage.api.cloudsploit.com",
			UILogin: "https://cloud-dev.aquasec.com",
			ApiUrl:  "https://api.dev.supply-chain.cloud.aquasec.com",
		}
	case "eu":
		return EnvUrls{
			CspmUrl: "https://eu.api.cloudsploit.com",
			UILogin: "https://cloud-dev.aquasec.com",
			ApiUrl:  "https://api.eu.supply-chain.cloud.aquasec.com",
		}
	case "singapore":
		return EnvUrls{
			CspmUrl: "https://ap-1.api.cloudsploit.com",
			UILogin: "https://cloud-dev.aquasec.com",
			ApiUrl:  "https://api.ap-1.supply-chain.cloud.aquasec.com",
		}
	case "sydney":
		return EnvUrls{
			CspmUrl: "https://ap-2.api.cloudsploit.com",
			UILogin: "https://cloud-dev.aquasec.com",
			ApiUrl:  "https://api.ap-2.supply-chain.cloud.aquasec.com",
		}
	default:
		return EnvUrls{
			CspmUrl: "https://api.cloudsploit.com",
			UILogin: "https://cloud.aquasec.com",
			ApiUrl:  "https://api.supply-chain.cloud.aquasec.com",
		}
	}
}
