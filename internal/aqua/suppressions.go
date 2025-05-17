package aqua

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy/pkg/log"
)

func (ac *Client) GetSuppressions() (string, error) {
	logger := log.WithPrefix("suppressions")

	platformCreds, err := creds.LoadAquaPlatformCreds()
	if err != nil {
		return "", fmt.Errorf("failed to load credentials: %w", err)
	}

	if platformCreds == nil {
		return "", fmt.Errorf("no credentials found")
	}

	if platformCreds.ExpiresAt.Before(time.Now()) {
		logger.Debug("Credentials expired, refreshing")
		if err := ac.Login(platformCreds.AquaUsername, platformCreds.AquaPassword, platformCreds.Region); err != nil {
			return "", fmt.Errorf("failed to refresh credentials: %w", err)
		}
		platformCreds, err = creds.LoadAquaPlatformCreds()
		if err != nil {
			return "", fmt.Errorf("failed to load refreshed credentials: %w", err)
		}
	}

	envUrls := GetUrls(platformCreds.Region)
	req, err := http.NewRequest("GET", envUrls.ApiUrl+"/v2/build/suppressions", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+platformCreds.Token)

	resp, err := ac.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get suppressions: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	return string(content), nil
}
