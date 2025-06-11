package creds

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// skipCI skips the test if running in a CI environment
// This is useful to avoid running tests that require user interaction or keyring access etc
func skipCI(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("Skipping test in CI environment")
	}
}

func TestSetCreds(t *testing.T) {
	skipCI(t)

	tests := []struct {
		name    string
		creds   *AquaCreds
		wantErr bool
	}{
		{
			name: "valid creds",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "test-region",
				Token:      "test-token",
				ExpiresAt:  1234567890,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ensure that the creds are cleared at the end of the test
			defer func() { _ = Clear() }()

			err := tt.creds.Save()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestLoadCreds(t *testing.T) {
	skipCI(t)

	tests := []struct {
		name    string
		creds   *AquaCreds
		wantErr bool
	}{
		{
			name: "valid creds",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "test-region",
				Token:      "test-token",
				ExpiresAt:  1234567890,
			},
			wantErr: false,
		},
		{
			name:    "no creds",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ensure that the creds are cleared at the end of the test
			defer func() { _ = Clear() }()

			if tt.creds != nil {
				err := tt.creds.Save()
				require.NoError(t, err)
			}

			_, err := Load()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestClearCreds(t *testing.T) {
	skipCI(t)

	tests := []struct {
		name  string
		creds *AquaCreds
	}{
		{
			name: "valid creds",
			creds: &AquaCreds{
				AquaKey:    "test-key",
				AquaSecret: "test-secret",
				Region:     "test-region",
				Token:      "test-token",
				ExpiresAt:  1234567890,
			},
		},
		{
			name: "no creds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ensure that the creds are cleared at the end of the test
			defer func() { _ = Clear() }()

			if tt.creds != nil {
				require.NoError(t, tt.creds.Save())

				// ensure creds are there
				creds, err := Load()
				require.NoError(t, err)
				require.Equal(t, tt.creds.AquaKey, creds.AquaKey)
				require.Equal(t, tt.creds.AquaSecret, creds.AquaSecret)
				require.Equal(t, tt.creds.Region, creds.Region)
				require.Equal(t, tt.creds.Token, creds.Token)
				require.Equal(t, tt.creds.ExpiresAt, creds.ExpiresAt)
			}

			require.NoError(t, Clear())
			_, err := Load()
			require.Error(t, err)
		})
	}
}
