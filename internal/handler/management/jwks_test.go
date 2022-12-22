package management

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/pkix/pem"
	testsupport2 "github.com/dadrus/heimdall/internal/x/testsupport"
)

type JWKSTestSuite struct {
	suite.Suite
	rootCA1 *testsupport2.CA
	intCA1  *testsupport2.CA
	ee1     *testsupport2.EndEntity
	ee2     *testsupport2.EndEntity

	app *fiber.App
	ks  keystore.KeyStore
}

func (suite *JWKSTestSuite) SetupSuite() {
	var err error

	// ROOT CAs
	suite.rootCA1, err = testsupport2.NewRootCA("Test Root CA 1", time.Hour*24)
	suite.NoError(err)

	// INT CA
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA1Cert, err := suite.rootCA1.IssueCertificate(
		testsupport2.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport2.WithIsCA(),
		testsupport2.WithValidity(time.Now(), time.Hour*24),
		testsupport2.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA1 = testsupport2.NewCA(intCA1PrivKey, intCA1Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(suite.T(), err)
	ee1cert, err := suite.intCA1.IssueCertificate(
		testsupport2.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport2.WithValidity(time.Now(), time.Hour*24),
		testsupport2.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport2.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee1 = &testsupport2.EndEntity{Certificate: ee1cert, PrivKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	suite.ee2 = &testsupport2.EndEntity{PrivKey: ee2PrivKey}

	pemBytes, err := pem.BuildPEM(
		pem.WithECDSAPrivateKey(ee1PrivKey, pem.WithPEMHeader("X-Key-ID", "foo")),
		pem.WithX509Certificate(ee1cert),
		pem.WithECDSAPrivateKey(ee2PrivKey, pem.WithPEMHeader("X-Key-ID", "bar")),
		pem.WithX509Certificate(intCA1Cert),
		pem.WithX509Certificate(suite.rootCA1.Certificate),
	)
	suite.NoError(err)

	suite.ks, err = keystore.NewKeyStoreFromPEMBytes(pemBytes, "")
	suite.NoError(err)

	suite.app = newApp(appArgs{
		Config:     &config.Configuration{Serve: config.ServeConfig{Management: config.ServiceConfig{}}},
		Registerer: prometheus.NewRegistry(),
		Logger:     log.Logger,
	})

	_, err = newHandler(handlerArgs{
		App:      suite.app,
		Logger:   log.Logger,
		KeyStore: suite.ks,
	})
	suite.NoError(err)
}

func (suite *JWKSTestSuite) TearDownSuite() {
	suite.NoError(suite.app.Shutdown())
}

func TestJWKSTestSuite(t *testing.T) {
	suite.Run(t, new(JWKSTestSuite))
}

func (suite *JWKSTestSuite) TestJWKSRequestWithoutEtagUsage() {
	// WHEN
	resp, err := suite.app.Test(
		httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/.well-known/jwks", nil),
		-1)

	// THEN
	require.NoError(suite.T(), err)
	require.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&jwks)
	require.NoError(suite.T(), err)

	require.Len(suite.T(), jwks.Keys, 2)

	jwk := jwks.Key("bar")
	require.Len(suite.T(), jwk, 1)
	entry, err := suite.ks.GetKey("bar")
	require.NoError(suite.T(), err)

	expected := entry.JWK()
	assert.Equal(suite.T(), expected.KeyID, jwk[0].KeyID)
	assert.Equal(suite.T(), expected.Key, jwk[0].Key)
	assert.Equal(suite.T(), expected.Algorithm, jwk[0].Algorithm)
	assert.Equal(suite.T(), expected.Use, jwk[0].Use)
	assert.Empty(suite.T(), jwk[0].Certificates)
	assert.Nil(suite.T(), jwk[0].CertificatesURL)
	assert.Empty(suite.T(), jwk[0].CertificateThumbprintSHA1)
	assert.Empty(suite.T(), jwk[0].CertificateThumbprintSHA256)

	jwk = jwks.Key("foo")
	require.Len(suite.T(), jwk, 1)
	entry, err = suite.ks.GetKey("foo")
	require.NoError(suite.T(), err)

	expected = entry.JWK()
	assert.Equal(suite.T(), expected.KeyID, jwk[0].KeyID)
	assert.Equal(suite.T(), expected.Key, jwk[0].Key)
	assert.Equal(suite.T(), expected.Algorithm, jwk[0].Algorithm)
	assert.Equal(suite.T(), expected.Use, jwk[0].Use)
	assert.Len(suite.T(), jwk[0].Certificates, 3)
	assert.Equal(suite.T(), expected.Certificates[0], jwk[0].Certificates[0])
	assert.Equal(suite.T(), expected.Certificates[1], jwk[0].Certificates[1])
	assert.Equal(suite.T(), expected.Certificates[2], jwk[0].Certificates[2])
	assert.Nil(suite.T(), jwk[0].CertificatesURL)
	assert.Empty(suite.T(), jwk[0].CertificateThumbprintSHA1)
	assert.Empty(suite.T(), jwk[0].CertificateThumbprintSHA256)
}

func (suite *JWKSTestSuite) TestJWKSRequestWithEtagUsage() {
	// GIVEN
	resp1, err := suite.app.Test(
		httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/.well-known/jwks", nil),
		-1)
	require.NoError(suite.T(), err)

	defer resp1.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp1.StatusCode)

	etagValue := resp1.Header.Get("ETag")
	require.NotEmpty(suite.T(), etagValue)

	req := httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/.well-known/jwks", nil)
	req.Header.Set("If-None-Match", etagValue)

	// WHEN
	resp2, err := suite.app.Test(req, -1)

	// THEN
	require.NoError(suite.T(), err)

	defer resp2.Body.Close()

	assert.Equal(suite.T(), http.StatusNotModified, resp2.StatusCode)
	assert.Empty(suite.T(), resp2.Header.Get("Content-Length"))
}
