package commands

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthCommand(t *testing.T) {
	cmd := NewAuthCommand()
	assert.Equal(t, "auth", cmd.Use)
	assert.Equal(t, "Auth tools for the Aqua Platform", cmd.Short)

	subCmds := cmd.Commands()
	require.Len(t, subCmds, 4)

	var foundLogin, foundLogout, foundStatus, foundToken bool
	for _, subCmd := range subCmds {
		switch subCmd.Use {
		case "login":
			foundLogin = true
		case "logout":
			foundLogout = true
		case "status":
			foundStatus = true
		case "token":
			foundToken = true
		}
	}
	assert.True(t, foundLogin)
	assert.True(t, foundLogout)
	assert.True(t, foundStatus)
	assert.True(t, foundToken)

	for _, subCmd := range subCmds {
		if subCmd.Use == "token" {
			assert.True(t, subCmd.Hidden)
		}
	}
}

func TestGetInput_existingValue(t *testing.T) {
	val, err := getInput("foo", "prompt: ", false)
	assert.NoError(t, err)
	assert.Equal(t, "foo", val)
}

func TestGetInput_emptyInput(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		_, err := w.Write([]byte("\n"))
		assert.NoError(t, err)
		require.NoError(t, w.Close())
	}()
	_, err := getInput("", "prompt: ", false)
	assert.Error(t, err)
}

func TestGetRegionFromList_existing(t *testing.T) {
	val, err := getRegionFromList("US")
	assert.NoError(t, err)
	assert.Equal(t, "US", val)
}

func TestGetRegionFromList_prompt(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		_, err := w.Write([]byte("1\n"))
		assert.NoError(t, err)
		require.NoError(t, w.Close())
	}()
	val, err := getRegionFromList("")
	assert.NoError(t, err)
	assert.Equal(t, "US", val)
}
