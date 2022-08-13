package keystore_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
)

func TestNewKeyStore(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp("", "test_ks.*")
	require.NoError(t, err)

	buf := bytes.NewBuffer(pemPKCS1ECPrivateKey)
	_, err = buf.Write(pemPKCS8RSAPrivateKey)
	require.NoError(t, err)

	err = os.WriteFile(file.Name(), buf.Bytes(), 0o600)
	require.NoError(t, err)

	defer os.Remove(file.Name())

	for _, tc := range []struct {
		uc     string
		conf   config.Configuration
		assert func(t *testing.T, ks keystore.KeyStore, err error)
	}{
		{
			uc: "signer not configured",
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)
				assert.Len(t, ks.Entries(), 1)
			},
		},
		{
			uc: "signer configured",
			conf: config.Configuration{
				Signer: config.SignerConfig{KeyStore: file.Name()},
			},
			assert: func(t *testing.T, ks keystore.KeyStore, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ks)
				assert.Len(t, ks.Entries(), 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			ks, err := keystore.NewKeyStore(tc.conf, log.Logger)

			// THEN
			tc.assert(t, ks, err)
		})
	}
}
