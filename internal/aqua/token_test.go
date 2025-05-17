package aqua

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestTokenParsing(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected JwtClaims
		wantErr  bool
	}{
		{
			name:  "valid token",
			token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE3MTU4NTYwMDAsImV4cCI6MTcxNTk0MjQwMH0.dummysignature`,
			expected: JwtClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:  "test-issuer",
					Subject: "1234567890",
					IssuedAt: &jwt.NumericDate{
						Time: time.Unix(1715856000, 0),
					},
					ExpiresAt: &jwt.NumericDate{
						Time: time.Unix(1715942400, 0),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTokenToClaim(tt.token)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected.Issuer, got.Issuer)
			require.Equal(t, tt.expected.Subject, got.Subject)
			require.Equal(t, tt.expected.IssuedAt.Time, got.IssuedAt.Time)
			require.Equal(t, tt.expected.ExpiresAt.Time, got.ExpiresAt.Time)
		})
	}
}
