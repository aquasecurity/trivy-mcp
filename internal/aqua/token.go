package aqua

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type LoginResponse struct {
	Status int `json:"status"`
	Code   int `json:"code"`
	Data   struct {
		Token string `json:"token"`
	} `json:"data"`
	AccountId    string `json:"account_id"`
	UserId       string `json:"user_id"`
	AccountAdmin bool   `json:"account_admin"`
	Email        string `json:"email"`
}

type KeySecretResponse struct {
	Status  int      `json:"status"`
	Message string   `json:"message"`
	Data    string   `json:"data,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

type JwtClaims struct {
	jwt.RegisteredClaims
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

func parseTokenToClaim(token string) (JwtClaims, error) {
	// Assuming the response is a JSON string
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JwtClaims{}, errors.New("invalid JWT token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return JwtClaims{}, errors.New("failed to decode JWT payload")
	}

	var claims JwtClaims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return JwtClaims{}, errors.New("failed to unmarshal JWT claims")
	}

	return claims, nil
}
