package management

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
)

func TestHealthRequest(t *testing.T) {
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

	// WHEN
	resp, err := app.Test(
		httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/.well-known/health", nil),
		-1)

	// THEN
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.JSONEq(t, `{ "status": "ok"}`, string(rawResp))
}
