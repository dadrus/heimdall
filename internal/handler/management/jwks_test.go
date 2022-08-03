package management

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
)

func TestJWKSRequestWithoutEtagUsage(t *testing.T) {
	// GIVEN
	const rsa2048 = 2048

	privateKey, err := rsa.GenerateKey(rand.Reader, rsa2048)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromKey(privateKey)
	require.NoError(t, err)

	app := newFiberApp(
		config.Configuration{Serve: config.ServeConfig{Management: config.ServiceConfig{}}},
		log.Logger)
	_, err = newHandler(handlerParams{
		App:      app,
		Logger:   log.Logger,
		KeyStore: ks,
	})
	require.NoError(t, err)

	// WHEN
	resp, err := app.Test(
		httptest.NewRequest("GET", "http://heimdall.test.local/.well-known/jwks", nil),
		-1)

	// THEN
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&jwks)
	require.NoError(t, err)

	assert.Len(t, jwks.Keys, 1)
	jwk := jwks.Key(ks.Entries()[0].KeyID)
	assert.Len(t, jwk, 1)

	expected := ks.Entries()[0].JWK()
	assert.Equal(t, expected.KeyID, jwk[0].KeyID)
	assert.Equal(t, expected.Key, jwk[0].Key)
	assert.Equal(t, expected.Algorithm, jwk[0].Algorithm)
	assert.Equal(t, expected.Use, jwk[0].Use)
	assert.Empty(t, jwk[0].Certificates)
	assert.Nil(t, jwk[0].CertificatesURL)
	assert.Empty(t, jwk[0].CertificateThumbprintSHA1)
	assert.Empty(t, jwk[0].CertificateThumbprintSHA256)
}

func TestJWKSRequestWithEtagUsage(t *testing.T) {
	// GIVEN
	const rsa2048 = 2048

	privateKey, err := rsa.GenerateKey(rand.Reader, rsa2048)
	require.NoError(t, err)

	ks, err := keystore.NewKeyStoreFromKey(privateKey)
	require.NoError(t, err)

	app := newFiberApp(
		config.Configuration{Serve: config.ServeConfig{Management: config.ServiceConfig{}}},
		log.Logger,
	)
	_, err = newHandler(handlerParams{
		App:      app,
		Logger:   log.Logger,
		KeyStore: ks,
	})
	require.NoError(t, err)

	resp1, err := app.Test(
		httptest.NewRequest("GET", "http://heimdall.test.local/.well-known/jwks", nil),
		-1)

	require.NoError(t, err)

	defer resp1.Body.Close()

	require.Equal(t, http.StatusOK, resp1.StatusCode)

	etagValue := resp1.Header.Get("ETag")
	require.NotEmpty(t, etagValue)

	req := httptest.NewRequest("GET", "http://heimdall.test.local/.well-known/jwks", nil)
	req.Header.Set("If-None-Match", etagValue)

	// WHEN
	resp2, err := app.Test(req, -1)

	// THEN
	require.NoError(t, err)

	defer resp2.Body.Close()

	assert.Equal(t, http.StatusNotModified, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("Content-Length"))
}
