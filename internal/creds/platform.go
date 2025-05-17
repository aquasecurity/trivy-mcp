package creds

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/zalando/go-keyring"
)

type AquaPlatformCreds struct {
	AquaUsername string     `json:"aqua_username"`
	AquaPassword string     `json:"aqua_password"`
	Region       string     `json:"region"`
	Token        string     `json:"token"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

// Save stores the credentials to the platform specific keyring
// and encodes them in base64. The credentials are stored as a JSON object.
func (c *AquaPlatformCreds) Save() error {
	logger := log.WithPrefix("aqua")
	logger.Debug("Saving Aqua username and password")
	// store the whole credential object in the keyring
	content, err := json.Marshal(c)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	return keyring.Set("trivy-mcp-aqua", "aqua_platform_creds", encoded)
}

func (c *AquaPlatformCreds) GenerateToken() (string, error) {
	// This method is not implemented for username and password credentials
	return "", nil
}
