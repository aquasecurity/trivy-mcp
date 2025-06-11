package creds

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJWT(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name:    "valid JWT",
			jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: false,
		},
		{
			name:    "invalid JWT format",
			jwt:     "invalid-jwt",
			wantErr: true,
		},
		{
			name:    "invalid JWT payload",
			jwt:     "header.invalid-payload.signature",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := decodeJWT(tt.jwt)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, claims)
		})
	}
}

func TestComputeHmac256(t *testing.T) {
	tests := []struct {
		name    string
		message string
		secret  string
		want    string
		wantErr bool
	}{
		{
			name:    "valid computation",
			message: "test message",
			secret:  "test secret",
			want:    "b5664a92da7fef821fa7ff75c00f711ba615dcb610de82edc440bc1337e251ef",
			wantErr: false,
		},
		{
			name:    "empty message",
			message: "",
			secret:  "test secret",
			want:    "18914c0590232ac230ffa391cacdf29978282fd411ba0173587c59e607cb4af7",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := computeHmac256(tt.message, tt.secret)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestGenerateToken(t *testing.T) {
	skipCI(t)

	tests := []struct {
		name      string
		creds     *AquaCreds
		wantToken bool
		wantErr   bool
	}{
		{
			name: "valid with existing valid token",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "test-region",
				Token:      "test-token",
				ExpiresAt:  time.Now().Add(time.Hour).Unix(), // future expiry
			},
			wantToken: true,
			wantErr:   false,
		},
		{
			name: "valid with expired token",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "test-region",
				Token:      "test-token",
				ExpiresAt:  time.Now().Add(-time.Hour).Unix(), // past expiry
			},
			wantToken: false,
			wantErr:   true, // Will fail on Verify() since test-key and test-secret aren't valid
		},
		{
			name: "missing credentials",
			creds: &AquaCreds{
				Region: "test-region",
			},
			wantToken: false,
			wantErr:   true,
		},
		{
			name: "missing region",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
			},
			wantToken: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.creds.GenerateToken()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantToken {
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	skipCI(t)

	tests := []struct {
		name    string
		creds   *AquaCreds
		wantErr bool
	}{
		{
			name: "missing credentials",
			creds: &AquaCreds{
				Region: "test-region",
			},
			wantErr: true,
		},
		{
			name: "invalid credentials",
			creds: &AquaCreds{
				AquaKey:    "invalid-key",
				AquaSecret: "invalid-secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.creds.Verify()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			// Valid credentials would be tested here, but we don't have real credentials for testing
		})
	}
}

func TestGetUrls(t *testing.T) {
	tests := []struct {
		name            string
		region          string
		expectedSCSURL  string
		expectedCSPMURL string
	}{
		{
			name:            "default region",
			region:          "",
			expectedSCSURL:  "https://api.supply-chain.cloud.aquasec.com",
			expectedCSPMURL: "https://api.cloudsploit.com",
		},
		{
			name:            "dev region",
			region:          "dev",
			expectedSCSURL:  "https://api.dev.supply-chain.cloud.aquasec.com",
			expectedCSPMURL: "https://stage.api.cloudsploit.com",
		},
		{
			name:            "eu region",
			region:          "eu",
			expectedSCSURL:  "https://api.eu-1.supply-chain.cloud.aquasec.com",
			expectedCSPMURL: "https://eu-1.api.cloudsploit.com",
		},
		{
			name:            "singapore region",
			region:          "singapore",
			expectedSCSURL:  "https://api.ap-1.supply-chain.cloud.aquasec.com",
			expectedCSPMURL: "https://ap-1.api.cloudsploit.com",
		},
		{
			name:            "sydney region",
			region:          "sydney",
			expectedSCSURL:  "https://api.ap-2.supply-chain.cloud.aquasec.com",
			expectedCSPMURL: "https://ap-2.api.cloudsploit.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := &AquaCreds{Region: tt.region}
			scsURL, cspmURL := creds.GetUrls()
			assert.Equal(t, tt.expectedSCSURL, scsURL)
			assert.Equal(t, tt.expectedCSPMURL, cspmURL)
		})
	}
}

func TestGetRawMessageData(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "test data",
			expected: "test data",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "json string",
			input:    `{"status":200,"message":"success","data":"token123"}`,
			expected: `{"status":200,"message":"success","data":"token123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRawMessageData(io.NopCloser(strings.NewReader(tt.input)))
			assert.Equal(t, tt.expected, result)
		})
	}
}
