// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type JWKSTestSuite struct {
	suite.Suite
	rootCA1 *testsupport.CA
	intCA1  *testsupport.CA
	ee1     *testsupport.EndEntity
	ee2     *testsupport.EndEntity

	srv *httptest.Server
	ks  keystore.KeyStore
}

func (suite *JWKSTestSuite) SetupSuite() {
	var err error

	// ROOT CAs
	suite.rootCA1, err = testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	suite.NoError(err)

	// INT CA
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	intCA1Cert, err := suite.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.NoError(err)
	suite.intCA1 = testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(suite.T(), err)
	ee1cert, err := suite.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.NoError(err)
	suite.ee1 = &testsupport.EndEntity{Certificate: ee1cert, PrivKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.NoError(err)
	suite.ee2 = &testsupport.EndEntity{PrivKey: ee2PrivKey}

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", "foo")),
		pemx.WithX509Certificate(ee1cert),
		pemx.WithECDSAPrivateKey(ee2PrivKey, pemx.WithHeader("X-Key-ID", "bar")),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(suite.rootCA1.Certificate),
	)
	suite.NoError(err)

	suite.ks, err = keystore.NewKeyStoreFromPEMBytes(pemBytes, "")
	suite.NoError(err)

	keys := make([]jose.JSONWebKey, len(suite.ks.Entries()))

	for idx, entry := range suite.ks.Entries() {
		keys[idx] = entry.JWK()
	}

	signer := mocks.NewJWTSignerMock(suite.T())
	signer.EXPECT().Keys().Return(keys)

	suite.srv = httptest.NewServer(newManagementHandler(signer))
}

func (suite *JWKSTestSuite) TearDownSuite() {
	suite.srv.Close()
}

func TestJWKSTestSuite(t *testing.T) {
	suite.Run(t, new(JWKSTestSuite))
}

func (suite *JWKSTestSuite) TestJWKSRequestWithoutEtagUsage() {
	// WHEN
	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.srv.URL+"/.well-known/jwks", nil)
	require.NoError(suite.T(), err)

	resp, err := client.Do(req)

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
	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.srv.URL+"/.well-known/jwks", nil)
	require.NoError(suite.T(), err)

	resp1, err := client.Do(req)
	require.NoError(suite.T(), err)

	defer resp1.Body.Close()

	require.Equal(suite.T(), http.StatusOK, resp1.StatusCode)

	etagValue := resp1.Header.Get("ETag")
	require.NotEmpty(suite.T(), etagValue)

	req, err = http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.srv.URL+"/.well-known/jwks", nil)
	require.NoError(suite.T(), err)
	req.Header.Set("If-None-Match", etagValue)

	// WHEN
	resp2, err := client.Do(req)

	// THEN
	require.NoError(suite.T(), err)

	defer resp2.Body.Close()

	assert.Equal(suite.T(), http.StatusNotModified, resp2.StatusCode)
	assert.Empty(suite.T(), resp2.Header.Get("Content-Length"))
}
