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
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/keystore"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type ServiceTestSuite struct {
	suite.Suite
	rootCA1 *testsupport.CA
	intCA1  *testsupport.CA
	ee1     *testsupport.EndEntity
	ee2     *testsupport.EndEntity

	srv    *http.Server
	ks     keystore.KeyStore
	signer *mocks.JWTSignerMock
	addr   string
}

func (suite *ServiceTestSuite) SetupSuite() {
	var err error

	// ROOT CAs
	suite.rootCA1, err = testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	suite.Require().NoError(err)

	// INT CA
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	intCA1Cert, err := suite.rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	suite.Require().NoError(err)
	suite.intCA1 = testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	// EE CERTS
	ee1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	ee1cert, err := suite.intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test EE 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*24),
		testsupport.WithSubjectPubKey(&ee1PrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	suite.Require().NoError(err)
	suite.ee1 = &testsupport.EndEntity{Certificate: ee1cert, PrivKey: ee1PrivKey}

	ee2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)
	suite.ee2 = &testsupport.EndEntity{PrivKey: ee2PrivKey}

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(ee1PrivKey, pemx.WithHeader("X-Key-ID", "foo")),
		pemx.WithX509Certificate(ee1cert),
		pemx.WithECDSAPrivateKey(ee2PrivKey, pemx.WithHeader("X-Key-ID", "bar")),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(suite.rootCA1.Certificate),
	)
	suite.Require().NoError(err)

	suite.ks, err = keystore.NewKeyStoreFromPEMBytes(pemBytes, "")
	suite.Require().NoError(err)
}

func (suite *ServiceTestSuite) SetupTest() {
	port, err := testsupport.GetFreePort()
	suite.Require().NoError(err)

	conf := &config.Configuration{
		Serve: config.ServeConfig{
			Management: config.ServiceConfig{
				Host: "127.0.0.1",
				Port: port,
				CORS: &config.CORS{},
			},
		},
		Metrics: config.MetricsConfig{Enabled: true},
	}

	listener, err := listener.New("tcp", conf.Serve.Management.Address(), conf.Serve.Management.TLS)
	suite.Require().NoError(err)
	suite.addr = "http://" + listener.Addr().String()

	suite.signer = mocks.NewJWTSignerMock(suite.T())
	suite.srv = newService(conf, log.Logger, suite.signer)

	go func() {
		suite.srv.Serve(listener)
	}()

	time.Sleep(50 * time.Millisecond)
}

func (suite *ServiceTestSuite) TearDownTest() {
	suite.srv.Shutdown(context.Background())
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (suite *ServiceTestSuite) TestJWKSRequestWithoutEtagUsage() {
	// GIVEN
	keys := make([]jose.JSONWebKey, len(suite.ks.Entries()))
	for idx, entry := range suite.ks.Entries() {
		keys[idx] = entry.JWK()
	}

	suite.signer.EXPECT().Keys().Return(keys)

	// WHEN
	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
	suite.Require().NoError(err)

	resp, err := client.Do(req)

	// THEN
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&jwks)
	suite.Require().NoError(err)

	suite.Require().Len(jwks.Keys, 2)

	jwk := jwks.Key("bar")
	suite.Require().Len(jwk, 1)
	entry, err := suite.ks.GetKey("bar")
	suite.Require().NoError(err)

	expected := entry.JWK()
	suite.Equal(expected.KeyID, jwk[0].KeyID)
	suite.Equal(expected.Key, jwk[0].Key)
	suite.Equal(expected.Algorithm, jwk[0].Algorithm)
	suite.Equal(expected.Use, jwk[0].Use)
	suite.Empty(jwk[0].Certificates)
	suite.Nil(jwk[0].CertificatesURL)
	suite.Empty(jwk[0].CertificateThumbprintSHA1)
	suite.Empty(jwk[0].CertificateThumbprintSHA256)

	jwk = jwks.Key("foo")
	suite.Require().Len(jwk, 1)
	entry, err = suite.ks.GetKey("foo")
	suite.Require().NoError(err)

	expected = entry.JWK()
	suite.Equal(expected.KeyID, jwk[0].KeyID)
	suite.Equal(expected.Key, jwk[0].Key)
	suite.Equal(expected.Algorithm, jwk[0].Algorithm)
	suite.Equal(expected.Use, jwk[0].Use)
	suite.Require().Len(jwk[0].Certificates, 3)
	suite.Equal(expected.Certificates[0], jwk[0].Certificates[0])
	suite.Equal(expected.Certificates[1], jwk[0].Certificates[1])
	suite.Equal(expected.Certificates[2], jwk[0].Certificates[2])
	suite.Nil(jwk[0].CertificatesURL)
	suite.Empty(jwk[0].CertificateThumbprintSHA1)
	suite.Empty(jwk[0].CertificateThumbprintSHA256)
}

func (suite *ServiceTestSuite) TestJWKSRequestWithEtagUsage() {
	// GIVEN
	keys := make([]jose.JSONWebKey, len(suite.ks.Entries()))
	for idx, entry := range suite.ks.Entries() {
		keys[idx] = entry.JWK()
	}

	suite.signer.EXPECT().Keys().Return(keys)

	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
	suite.Require().NoError(err)

	resp1, err := client.Do(req)
	suite.Require().NoError(err)

	defer resp1.Body.Close()

	suite.Require().Equal(http.StatusOK, resp1.StatusCode)

	etagValue := resp1.Header.Get("ETag")
	suite.Require().NotEmpty(etagValue)

	req, err = http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
	suite.Require().NoError(err)
	req.Header.Set("If-None-Match", etagValue)

	// WHEN
	resp2, err := client.Do(req)

	// THEN
	suite.Require().NoError(err)

	defer resp2.Body.Close()

	suite.Equal(http.StatusNotModified, resp2.StatusCode)
	suite.Empty(resp2.Header.Get("Content-Length"))
}

func (suite *ServiceTestSuite) TestHealthRequest() {
	// GIVEN
	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, suite.addr+"/.well-known/health", nil)
	suite.Require().NoError(err)

	// WHEN
	resp, err := client.Do(req)

	// THEN
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)

	suite.JSONEq(`{ "status": "ok"}`, string(rawResp))
}
