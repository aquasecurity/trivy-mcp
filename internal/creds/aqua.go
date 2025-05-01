package creds

import (
	"encoding/base64"
	"strings"

	"github.com/zalando/go-keyring"
)

type AquaCreds struct {
	AquaKey    string `json:"aqua_key"`
	AquaSecret string `json:"aqua_secret"`
	Region     string `json:"region"`
}

func (c *AquaCreds) GetUrls() (string, string) {
	switch strings.ToLower(c.Region) {
	case "dev":
		return "https://api.dev.supply-chain.cloud.aquasec.com", "https://stage.api.cloudsploit.com"
	case "eu":
		return "https://api.eu-1.supply-chain.cloud.aquasec.com", "https://eu-1.api.cloudsploit.com"
	case "singapore":
		return "https://api.ap-1.supply-chain.cloud.aquasec.com", "https://ap-1.api.cloudsploit.com"
	case "sydney":
		return "https://api.ap-2.supply-chain.cloud.aquasec.com", "https://ap-2.api.cloudsploit.com"
	default:
		return "https://api.supply-chain.cloud.aquasec.com", "https://api.cloudsploit.com"
	}
}

func Clear() error {
	// Clear the credentials from the keyring
	if err := keyring.Delete("trivy-mcp-aqua", "aqua_key"); err != nil {
		return err
	}
	if err := keyring.Delete("trivy-mcp-aqua", "aqua_secret"); err != nil {
		return err
	}
	if err := keyring.Delete("trivy-mcp-aqua", "region"); err != nil {
		return err
	}
	return nil
}

// Save stores the credentials to disk with machine-specific encoding
func (c *AquaCreds) Save() error {
	encodedKey := base64.StdEncoding.EncodeToString([]byte(c.AquaKey))
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(c.AquaSecret))
	region := base64.StdEncoding.EncodeToString([]byte(c.Region))

	if err := keyring.Set("trivy-mcp-aqua", "aqua_key", encodedKey); err != nil {
		return err
	}

	if err := keyring.Set("trivy-mcp-aqua", "aqua_secret", encodedSecret); err != nil {
		return err
	}

	if err := keyring.Set("trivy-mcp-aqua", "region", region); err != nil {
		return err
	}
	return nil
}

// Load retrieves the credentials from disk
func Load() (*AquaCreds, error) {
	encodedKey, err := keyring.Get("trivy-mcp-aqua", "aqua_key")
	if err != nil {
		return nil, err
	}
	encodedSecret, err := keyring.Get("trivy-mcp-aqua", "aqua_secret")
	if err != nil {
		return nil, err
	}
	region, err := keyring.Get("trivy-mcp-aqua", "region")
	if err != nil {
		return nil, err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, err
	}
	decodedRegion, err := base64.StdEncoding.DecodeString(region)
	if err != nil {
		return nil, err
	}
	return &AquaCreds{
		AquaKey:    string(decodedKey),
		AquaSecret: string(decodedSecret),
		Region:     string(decodedRegion),
	}, nil
}
