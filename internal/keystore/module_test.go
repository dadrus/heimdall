package keystore_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
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
				entry := ks.Entries()[0]
				assert.IsType(t, &ecdsa.PrivateKey{}, entry.PrivateKey)
				assert.Equal(t, 384, entry.KeySize)
				assert.Equal(t, "ECDSA", entry.Alg)
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
				entry1 := ks.Entries()[0]
				assert.IsType(t, &ecdsa.PrivateKey{}, entry1.PrivateKey)
				assert.Equal(t, 256, entry1.KeySize)
				assert.Equal(t, "ECDSA", entry1.Alg)
				entry2 := ks.Entries()[1]
				assert.IsType(t, &rsa.PrivateKey{}, entry2.PrivateKey)
				assert.Equal(t, 2048, entry2.KeySize)
				assert.Equal(t, "RSA", entry2.Alg)
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
