package flag

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestAddMcpFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddMcpFlags(cmd)

	tests := []struct {
		name     string
		flagName string
		exists   bool
	}{
		{"transport flag", "transport", true},
		{"port flag", "port", true},
		{"trivy-binary flag", "trivy-binary", true},
		{"use-aqua-platform flag", "use-aqua-platform", true},
		{"nonexistent flag", "does-not-exist", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.flagName)
			if tt.exists {
				assert.NotNil(t, f)
			} else {
				assert.Nil(t, f)
			}
		})
	}
}

func TestAddBaseFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddBaseFlags(cmd)

	versionFlag := cmd.PersistentFlags().Lookup("version")
	assert.NotNil(t, versionFlag)
	assert.Equal(t, "Show version", versionFlag.Usage)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.NotNil(t, debugFlag)
	assert.Equal(t, "Enable debug mode", debugFlag.Usage)
}

func TestAddLoginFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddLoginFlags(cmd)

	aquaKeyFlag := cmd.Flags().Lookup("aqua-key")
	assert.NotNil(t, aquaKeyFlag)
	assert.Equal(t, "Aqua key", aquaKeyFlag.Usage)

	aquaSecretFlag := cmd.Flags().Lookup("aqua-secret")
	assert.NotNil(t, aquaSecretFlag)
	assert.Equal(t, "Aqua secret", aquaSecretFlag.Usage)

	aquaRegionFlag := cmd.Flags().Lookup("aqua-region")
	assert.NotNil(t, aquaRegionFlag)
	assert.Contains(t, aquaRegionFlag.Usage, "Aqua region")
}

func TestToOptions_Defaults(t *testing.T) {
	// The default values are set by the package-level vars
	opts := ToOptions()
	assert.Equal(t, false, opts.Debug)
	assert.Equal(t, false, opts.Quiet)
	assert.Equal(t, false, opts.ShowVersion)
	assert.Equal(t, "stdio", opts.Transport)
	assert.Equal(t, 23456, opts.SSEPort)
	assert.Equal(t, "", opts.TrivyBinary)
	assert.Equal(t, false, opts.UseAquaPlatform)
}

func TestToLoginOptions_Defaults(t *testing.T) {
	opts := ToLoginOptions()
	assert.Equal(t, "", opts.AquaKey)
	assert.Equal(t, "", opts.AquaSecret)
	assert.Equal(t, "", opts.AquaRegion)
}

func TestLoginOptions_ToAquaCreds(t *testing.T) {
	lo := LoginOptions{
		AquaKey:    "key",
		AquaSecret: "secret",
		AquaRegion: "region",
	}
	creds := lo.ToAquaCreds()
	assert.Equal(t, "key", creds.AquaKey)
	assert.Equal(t, "secret", creds.AquaSecret)
	assert.Equal(t, "region", creds.Region)
}
