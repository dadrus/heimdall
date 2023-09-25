// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package prometheus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRegisterCertificateExpiryCollector(t *testing.T) {
	t.Parallel()
	// GIVEN

	// Root CA
	rootCA1, err := testsupport.NewRootCA("Test Root CA 1", time.Hour*24)
	require.NoError(t, err)

	// INT CAs
	intCA1PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	intCA1Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 1",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*12),
		testsupport.WithSubjectPubKey(&intCA1PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA1 := testsupport.NewCA(intCA1PrivKey, intCA1Cert)

	intCA2PrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	intCA2Cert, err := rootCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Test Int CA 2",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithIsCA(),
		testsupport.WithValidity(time.Now(), time.Hour*12),
		testsupport.WithSubjectPubKey(&intCA2PrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	intCA2 := testsupport.NewCA(intCA2PrivKey, intCA2Cert)

	// EE CERTS
	decisionPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	decisionCert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Decision Service",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now(), time.Hour*1),
		testsupport.WithSubjectPubKey(&decisionPrivKey.PublicKey, x509.ECDSAWithSHA384))
	require.NoError(t, err)

	proxyPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	proxyCert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Proxy Service",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*1), time.Hour*2),
		testsupport.WithSubjectPubKey(&proxyPrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	managementPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	managementCert, err := intCA1.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Management Service",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*1), time.Hour*2),
		testsupport.WithSubjectPubKey(&managementPrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	signerPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	signerCert, err := intCA2.IssueCertificate(
		testsupport.WithSubject(pkix.Name{
			CommonName:   "Signer Service",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithValidity(time.Now().Add(-time.Hour*1), time.Hour*2),
		testsupport.WithSubjectPubKey(&signerPrivKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature))
	require.NoError(t, err)

	serveServicePEMBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(proxyPrivKey, pemx.WithHeader("X-Key-ID", "proxy")),
		pemx.WithX509Certificate(proxyCert),
		pemx.WithECDSAPrivateKey(decisionPrivKey, pemx.WithHeader("X-Key-ID", "decision")),
		pemx.WithX509Certificate(decisionCert),
		pemx.WithECDSAPrivateKey(managementPrivKey, pemx.WithHeader("X-Key-ID", "management")),
		pemx.WithX509Certificate(managementCert),
		pemx.WithX509Certificate(intCA1Cert),
		pemx.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	signerPEMBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(signerPrivKey),
		pemx.WithX509Certificate(signerCert),
		pemx.WithX509Certificate(intCA2Cert),
		pemx.WithX509Certificate(rootCA1.Certificate),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	serveServicesPEMFile, err := os.Create(filepath.Join(testDir, "serve.pem"))
	require.NoError(t, err)

	signerPEMFile, err := os.Create(filepath.Join(testDir, "sign.pem"))
	require.NoError(t, err)

	_, err = serveServicesPEMFile.Write(serveServicePEMBytes)
	require.NoError(t, err)

	_, err = signerPEMFile.Write(signerPEMBytes)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()

	// WHEN
	registerCertificateExpiryCollector(
		&config.Configuration{
			Serve: config.ServeConfig{
				Proxy: config.ServiceConfig{
					TLS: &config.TLS{
						KeyStore: config.KeyStore{Path: serveServicesPEMFile.Name()},
						KeyID:    "proxy",
					},
				},
				Decision: config.ServiceConfig{
					TLS: &config.TLS{
						KeyStore: config.KeyStore{Path: serveServicesPEMFile.Name()},
						KeyID:    "decision",
					},
				},
				Management: config.ServiceConfig{
					TLS: &config.TLS{
						KeyStore: config.KeyStore{Path: serveServicesPEMFile.Name()},
						KeyID:    "management",
					},
				},
			},
			Signer: config.SignerConfig{
				Name:     "foo",
				KeyStore: config.KeyStore{Path: signerPEMFile.Name()},
			},
		},
		reg,
	)

	// WHEN
	result, err := reg.Gather()

	// THEN
	require.NoError(t, err)
	require.Len(t, result, 1)

	metric := result[0]
	assert.Equal(t, "certificate_expiry_seconds", metric.GetName())
	assert.Equal(t, "Number of seconds until certificate expires", metric.GetHelp())
	assert.Equal(t, io_prometheus_client.MetricType_GAUGE, metric.GetType())

	values := metric.GetMetric()
	require.Len(t, values, 12)
}
