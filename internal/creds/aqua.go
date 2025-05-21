package creds

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

type AquaCreds struct {
	AquaKey    string `json:"aqua_key"`
	AquaSecret string `json:"aqua_secret"`
	Region     string `json:"region"`
	Token      string `json:"token"`
	ExpiresAt  int64  `json:"expires_at"`
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
	if err := keyring.Delete("trivy-mcp-aqua", "aqua-creds"); err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}

// Save stores the credentials to disk with machine-specific encoding
func (c *AquaCreds) Save() error {
	credJson, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(credJson)

	if err := keyring.Set("trivy-mcp-aqua", "aqua-creds", encoded); err != nil {
		return err
	}

	return nil
}

// Load retrieves the credentials from disk
func Load() (*AquaCreds, error) {
	encoded, err := keyring.Get("trivy-mcp-aqua", "aqua-creds")
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var creds AquaCreds
	if err := json.Unmarshal(decoded, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}
	return &creds, nil
}
