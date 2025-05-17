package creds

import (
	"encoding/base64"
	"encoding/json"

	"github.com/zalando/go-keyring"
)

type KeySecretCreds struct {
	AquaKey    string `json:"aqua_key"`
	AquaSecret string `json:"aqua_secret"`
	Region     string `json:"region"`
}

// Save stores the credentials to disk with machine-specific encoding
func (c *KeySecretCreds) Save() error {
	content, err := json.Marshal(c)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	return keyring.Set("trivy-mcp-aqua", "aqua_keysecret_creds", encoded)
}
