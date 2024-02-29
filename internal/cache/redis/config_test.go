package redis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCredentialsReload(t *testing.T) {
	t.Parallel()

	// GIVEN
	testDir := t.TempDir()

	cf1, err := os.Create(filepath.Join(testDir, "credentials1.yaml"))
	require.NoError(t, err)

	_, err = cf1.WriteString(`
username: oof
password: rab
`)
	require.NoError(t, err)

	cf2, err := os.Create(filepath.Join(testDir, "credentials2.yaml"))
	require.NoError(t, err)

	_, err = cf2.WriteString(`
username: foo
password: bar
`)
	require.NoError(t, err)

	cf3, err := os.Create(filepath.Join(testDir, "credentials3.yaml"))
	require.NoError(t, err)

	_, err = cf3.WriteString(`
  foo: bar
  bar: foo
`)
	require.NoError(t, err)

	fc := &fileCredentials{Path: cf1.Name()}

	// WHEN
	err = fc.load()

	// THEN
	require.NoError(t, err)

	assert.Equal(t, "oof", fc.creds.Username)
	assert.Equal(t, "rab", fc.creds.Password)

	// WHEN
	fc.Path = cf2.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)

	// WHEN
	fc.Path = cf3.Name()
	fc.OnChanged(log.Logger)

	// THEN
	assert.Equal(t, "foo", fc.creds.Username)
	assert.Equal(t, "bar", fc.creds.Password)
}
