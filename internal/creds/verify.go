package creds

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/golang-jwt/jwt/v5"
)

type Response struct {
	Status  int      `json:"status"`
	Message string   `json:"message"`
	Data    string   `json:"data,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

type JwtClaims struct {
	jwt.RegisteredClaims
}

func (c *AquaCreds) Verify() error {

	logger := log.WithPrefix("aqua")
	logger.Debug("Verifying Aqua credentials")

	if c.AquaKey == "" || c.AquaSecret == "" {
		return errors.New("aqua credentials are not set")
	}

	response, err := c.obtainJWT()
	if err != nil {
		return err
	}

	parts := strings.Split(response, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("failed to decode JWT payload")
	}
	var claims JwtClaims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return errors.New("failed to unmarshal JWT claims")
	}

	logger.Debug("Login credentials verified successfully")

	return nil
}

func (c *AquaCreds) obtainJWT() (string, error) {
	body := `{"validity":30,"allowed_endpoints":["ANY:v2/build/twirp/buildsecurity.BuildSecurity/*","ANY:v2/log*","ANY:api/*"]}`

	_, cspmUrl := c.GetUrls()

	// update the URL to use the CSPM endpoint
	tokenEndpoint := fmt.Sprintf("%s/v2/tokens", cspmUrl)

	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", err
	}

	timestampString := strconv.Itoa(int(time.Now().Unix()))
	someString := timestampString + "POST/v2/tokens" + body
	signature, err := computeHmac256(someString, c.AquaSecret)
	if err != nil {
		return "", err
	}

	req.Header.Add("x-signature", signature)
	req.Header.Add("x-timestamp", timestampString)
	req.Header.Add("x-api-key", c.AquaKey)

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("failed sending jwt request token with error: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	var response Response
	debugRawBody := getRawMessageData(resp.Body)              // read the body before decoding it
	resp.Body = io.NopCloser(strings.NewReader(debugRawBody)) // restore the body to be read again
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("failed decoding response with error: %w, raw response body: %s", err, debugRawBody)
	}

	if response.Status != 200 {
		var e = "unknown error"
		if len(response.Errors) > 0 {
			e = response.Errors[0]
		}
		return "", fmt.Errorf("failed to generate Aqua token with error: %s, %s", response.Message, e)
	}
	return response.Data, nil
}

func computeHmac256(message string, secret string) (string, error) {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", fmt.Errorf("failed writing hmac: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func getRawMessageData(rc io.ReadCloser) string {
	data, err := io.ReadAll(rc)
	if err != nil {
		fmt.Println("Error reading RawResponse io.ReadCloser:", err)
		return ""
	}

	return string(data)
}
