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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/listener"
	"github.com/dadrus/heimdall/internal/keymaterial/joseadapter"
	"github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

type ServiceTestSuite struct {
	suite.Suite

	rootCA1 *testsupport.CA
	intCA1  *testsupport.CA
	ee1     *testsupport.EndEntity
	ee2     *testsupport.EndEntity

	srv     *http.Server
	secret1 secrets.AsymmetricKeySecret
	secret2 secrets.AsymmetricKeySecret
	addr    string
	khr     *mocks.RegistryMock
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

	suite.secret1 = types.NewAsymmetricKeySecret("bar", "foo", ee1PrivKey,
		[]*x509.Certificate{ee1cert, intCA1Cert, suite.rootCA1.Certificate})
	suite.secret2 = types.NewAsymmetricKeySecret("bar", "bar", ee2PrivKey, nil)
}

func (suite *ServiceTestSuite) SetupTest() {
	port, err := testsupport.GetFreePort()
	suite.Require().NoError(err)

	conf := &config.Configuration{
		Management: config.ManagementConfig{
			Host: "127.0.0.1",
			Port: port,
			CORS: &config.CORS{},
			Requests: config.IngressRequests{
				MaxInFlight: 1,
				Body: config.IngressRequestBody{
					MaxSize: 5 * bytesize.B,
				},
			},
		},
		Metrics: config.MetricsConfig{Enabled: true},
	}

	factory, err := listener.NewFactory(
		conf.Management.Address(),
		conf.Management.TLS,
		0,
		nil,
	)
	suite.Require().NoError(err)

	listener, err := factory.Create(suite.T().Context())
	suite.Require().NoError(err)
	suite.addr = "http://" + listener.Addr().String()

	suite.khr = mocks.NewRegistryMock(suite.T())
	suite.srv = newService(conf, log.Logger, suite.khr)

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
	var err error

	keys := make([]jose.JSONWebKey, 2)
	for idx, entry := range []secrets.AsymmetricKeySecret{suite.secret1, suite.secret2} {
		keys[idx], err = joseadapter.ToJWK(entry)
		suite.Require().NoError(err)
	}

	suite.khr.EXPECT().Keys().Return(keys)

	// WHEN
	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(suite.T().Context(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
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

	expected, err := joseadapter.ToJWK(suite.secret2)
	suite.Require().NoError(err)
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

	expected, err = joseadapter.ToJWK(suite.secret1)
	suite.Require().NoError(err)
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
	var err error

	keys := make([]jose.JSONWebKey, 2)
	for idx, entry := range []secrets.AsymmetricKeySecret{suite.secret1, suite.secret2} {
		keys[idx], err = joseadapter.ToJWK(entry)
		suite.Require().NoError(err)
	}

	suite.khr.EXPECT().Keys().Return(keys)

	client := &http.Client{Transport: &http.Transport{}}
	req, err := http.NewRequestWithContext(suite.T().Context(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
	suite.Require().NoError(err)

	resp1, err := client.Do(req)
	suite.Require().NoError(err)

	defer resp1.Body.Close()

	suite.Require().Equal(http.StatusOK, resp1.StatusCode)

	etagValue := resp1.Header.Get("ETag")
	suite.Require().NotEmpty(etagValue)

	req, err = http.NewRequestWithContext(suite.T().Context(), http.MethodGet, suite.addr+"/.well-known/jwks", nil)
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
	req, err := http.NewRequestWithContext(suite.T().Context(), http.MethodGet, suite.addr+"/.well-known/health", nil)
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

func (suite *ServiceTestSuite) TestRequestBodyLimit() {
	// GIVEN
	client := &http.Client{Transport: &http.Transport{}}

	req, err := http.NewRequestWithContext(
		suite.T().Context(),
		http.MethodGet,
		suite.addr+"/.well-known/jwks",
		strings.NewReader("123456"),
	)
	suite.Require().NoError(err)

	// WHEN
	resp, err := client.Do(req)

	// THEN
	suite.Require().NoError(err)

	defer resp.Body.Close()

	suite.Equal(http.StatusRequestEntityTooLarge, resp.StatusCode)

	rawResp, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	suite.Empty(rawResp)
}

func (suite *ServiceTestSuite) TestRequestLimit() {
	// GIVEN
	requestEntered := make(chan struct{})
	releaseRequest := make(chan struct{})

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseRequest)
		})
	}
	suite.T().Cleanup(release)

	suite.khr.EXPECT().Keys().Once().
		Run(func(_ mock.Arguments) {
			close(requestEntered)

			<-releaseRequest
		}).
		Return([]jose.JSONWebKey{})

	client := &http.Client{Transport: &http.Transport{}}

	firstResponse := make(chan *http.Response, 1)
	firstError := make(chan error, 1)

	go func() {
		req, err := http.NewRequestWithContext(
			suite.T().Context(),
			http.MethodGet,
			suite.addr+"/.well-known/jwks",
			nil,
		)
		if err != nil {
			firstError <- err

			return
		}

		resp, err := client.Do(req) //nolint:bodyclose

		firstResponse <- resp
		firstError <- err
	}()

	select {
	case <-requestEntered:
	case <-time.After(time.Second):
		suite.FailNow("first request did not enter management handler")
	}

	secondRequest, err := http.NewRequestWithContext(
		suite.T().Context(),
		http.MethodGet,
		suite.addr+"/.well-known/health",
		nil,
	)
	suite.Require().NoError(err)

	// WHEN
	secondResponse, err := client.Do(secondRequest)

	// THEN
	suite.Require().NoError(err)
	suite.Require().NotNil(secondResponse)

	defer secondResponse.Body.Close()

	suite.Equal(http.StatusTooManyRequests, secondResponse.StatusCode)

	data, err := io.ReadAll(secondResponse.Body)
	suite.Require().NoError(err)
	suite.Empty(data)

	// WHEN
	release()

	// THEN
	select {
	case err := <-firstError:
		suite.Require().NoError(err)
	case <-time.After(time.Second):
		suite.FailNow("first request did not complete")
	}

	select {
	case resp := <-firstResponse:
		suite.Require().NotNil(resp)
		defer resp.Body.Close()

		suite.Equal(http.StatusOK, resp.StatusCode)
	case <-time.After(time.Second):
		suite.FailNow("first response was not received")
	}
}

func TestNewService(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tls   *config.TLS
		http2 bool
	}{
		"cleartext enables http1 only": {},
		"tls enables http1 and http2": {
			tls:   &config.TLS{},
			http2: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			conf := &config.Configuration{}

			conf.Management.TLS = tc.tls
			conf.Management.Timeout.Read = 98 * time.Second
			conf.Management.Timeout.Write = 99 * time.Second
			conf.Management.Requests.ReadTimeout = 10 * time.Second
			conf.Management.Requests.Headers.MaxSize = 42 * bytesize.KB
			conf.Management.Requests.Headers.ReadTimeout = 11 * time.Second
			conf.Management.Responses.WriteTimeout = 12 * time.Second
			conf.Management.Responses.WriteIdleTimeout = 14 * time.Second
			conf.Management.Connections.IdleTimeout = 13 * time.Second

			// WHEN
			srv := newService(
				conf,
				log.Logger,
				nil,
			)

			// THEN
			assert.Equal(t, 10*time.Second, srv.ReadTimeout)
			assert.Equal(t, 11*time.Second, srv.ReadHeaderTimeout)
			assert.Equal(t, 12*time.Second, srv.WriteTimeout)
			assert.Equal(t, 13*time.Second, srv.IdleTimeout)
			assert.Equal(t, int(42*bytesize.KB), srv.MaxHeaderBytes)

			require.NotNil(t, srv.HTTP2)
			assert.Equal(t, 100, srv.HTTP2.MaxConcurrentStreams)
			assert.Equal(t, 30*time.Second, srv.HTTP2.SendPingTimeout)
			assert.Equal(t, 15*time.Second, srv.HTTP2.PingTimeout)
			assert.Equal(t, 30*time.Second, srv.HTTP2.WriteByteTimeout)

			require.NotNil(t, srv.Protocols)
			assert.True(t, srv.Protocols.HTTP1())
			assert.Equal(t, tc.http2, srv.Protocols.HTTP2())
			assert.False(t, srv.Protocols.UnencryptedHTTP2())

			assert.NotNil(t, srv.Handler)
			assert.NotNil(t, srv.ErrorLog)
		})
	}
}
