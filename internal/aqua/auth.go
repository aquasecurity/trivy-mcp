package aqua

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy-mcp/internal/creds"
	"github.com/aquasecurity/trivy/pkg/log"
)

func (ac *Client) Login(username, password, region string) error {
	envUrls := GetUrls(region)

	body := fmt.Sprintf(`{"email":"%s","password":"%s"}`, username, password)
	req, err := http.NewRequest("POST", envUrls.UILogin+"/api/v2/signin", bytes.NewBuffer([]byte(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed sending jwt request token with error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to login with error: %s", resp.Status)
	}

	defer func() { _ = resp.Body.Close() }()
	var response LoginResponse

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed decoding response with error: %w", err)
	}

	claims, err := parseTokenToClaim(response.Data.Token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	credentials := creds.AquaPlatformCreds{
		AquaUsername: username,
		AquaPassword: password,
		Token:        response.Data.Token,
		Region:       region,
		ExpiresAt:    &claims.ExpiresAt.Time,
	}

	return credentials.Save()
}

type generateKeyResponse struct {
	Data struct {
		AquaKey    string `json:"access_key"`
		AquaSecret string `json:"secret"`
	} `json:"data"`
}

func (ac *Client) CreateKeySecretCreds() error {
	logger := log.WithPrefix("aqua")
	aquaCreds, err := creds.LoadAquaPlatformCreds()
	if err != nil {
		return fmt.Errorf("failed to load Aqua platform credentials: %w", err)
	}

	urls := GetUrls(aquaCreds.Region)
	descrption := fmt.Sprintf(`{"description": "%s-mcp-keypair"}`, os.Getenv("USER"))
	url := fmt.Sprintf("%s/v2/apikeys", urls.CspmUrl)
	// create some new creds
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(descrption)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", aquaCreds.Token))
	resp, err := ac.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed sending jwt request token with error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to generate Aqua token with error: %s", resp.Status)
	}
	var response generateKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed decoding response with error: %w", err)
	}

	logger.Debug("Aqua key and secret created successfully")
	ksCreds := creds.KeySecretCreds{
		AquaKey:    response.Data.AquaKey,
		AquaSecret: response.Data.AquaSecret,
		Region:     aquaCreds.Region,
	}

	return ksCreds.Save()
}

func (ac *Client) VerifyKeySecretCreds() error {
	logger := log.WithPrefix("aqua")
	credentials, err := creds.LoadKeySecretCreds()
	if err != nil {
		return fmt.Errorf("failed to load Aqua platform credentials: %w", err)
	}

	body := `{"validity":30,"allowed_endpoints":["ANY:v2/build/twirp/buildsecurity.BuildSecurity/*","ANY:v2/log*","ANY:api/*","ANY:v2/build/*"]}`
	urls := GetUrls(credentials.Region)
	url := fmt.Sprintf("%s/v2/tokens", urls.CspmUrl)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))

	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	timestampString := strconv.Itoa(int(time.Now().Unix()))
	someString := timestampString + "POST/v2/tokens" + body
	signature, err := computeHmac256(someString, credentials.AquaSecret)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}

	req.Header.Add("x-signature", signature)
	req.Header.Add("x-timestamp", timestampString)
	req.Header.Add("x-api-key", credentials.AquaKey)

	resp, err := ac.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed sending jwt request token with error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to verify key secret credentials with error: %s", resp.Status)
	}

	logger.Debug("Aqua key and secret verified successfully")
	return nil
}
