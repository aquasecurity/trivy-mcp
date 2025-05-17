package creds

import (
	"encoding/base64"
	"encoding/json"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/zalando/go-keyring"
)

func Clear() error {
	// Clear the credentials from the keyring
	if err := keyring.Delete("trivy-mcp-aqua", "aqua_platform_creds"); err != nil && err != keyring.ErrNotFound {
		return err
	}
	if err := keyring.Delete("trivy-mcp-aqua", "aqua_keysecret_creds"); err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}

// LoadAquaPlatformCreds retrieves the credentials from keyring
func LoadAquaPlatformCreds() (*AquaPlatformCreds, error) {
	logger := log.WithPrefix("aqua")
	logger.Debug("Loading Aqua username and password")

	encoded, err := keyring.Get("trivy-mcp-aqua", "aqua_platform_creds")
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var userPassCreds = &AquaPlatformCreds{}
	if err := json.Unmarshal(decoded, userPassCreds); err != nil {
		return nil, err
	}

	return userPassCreds, nil
}

// LoadKeySecretCreds retrieves the credentials from keyring
func LoadKeySecretCreds() (*KeySecretCreds, error) {
	encoded, err := keyring.Get("trivy-mcp-aqua", "aqua_keysecret_creds")
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var keySecretCreds = &KeySecretCreds{}
	if err := json.Unmarshal(decoded, keySecretCreds); err != nil {
		return nil, err
	}
	return keySecretCreds, nil
}
