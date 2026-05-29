package pem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/provider"
)

func TestReadFile(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T) string
		assert func(t *testing.T, data []byte, err error)
	}{
		"reads file contents": {
			setup: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "data.pem")

				require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

				return path
			},
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []byte("content"), data)
			},
		},
		"returns configuration error if path does not exist": {
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing.pem")
			},
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "failed to get information about")
				require.Nil(t, data)
			},
		},
		"returns configuration error if path is directory": {
			setup: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			assert: func(t *testing.T, data []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, provider.ErrConfiguration)
				require.ErrorContains(t, err, "is not a file")
				require.Nil(t, data)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			path := tc.setup(t)

			data, err := readFile(path)

			tc.assert(t, data, err)
		})
	}
}
