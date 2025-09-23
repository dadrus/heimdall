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

package webhooks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestControllerLifecycle(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()

	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	serverCert, err := testsupport.NewCertificateBuilder(
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&serverKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSignaturePrivKey(serverKey),
		testsupport.WithKeyUsage(x509.KeyUsageDigitalSignature),
		testsupport.WithExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
		testsupport.WithGeneratedSubjectKeyID(),
		testsupport.WithIPAddresses([]net.IP{net.ParseIP("127.0.0.1")}),
		testsupport.WithSelfSigned(),
	).Build()
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(serverKey),
		pemx.WithX509Certificate(serverCert),
	)
	require.NoError(t, err)

	pemFile, err := os.Create(filepath.Join(testDir, "keystore.pem"))
	require.NoError(t, err)

	_, err = pemFile.Write(pemBytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(serverCert)

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
			ForceAttemptHTTP2: true,
		},
	}

	notTLSClient := &http.Client{}

	for uc, tc := range map[string]struct {
		tls     *config.TLS
		request func(t *testing.T, baseURL string) *http.Request
		assert  func(t *testing.T, err error, resp *http.Response)
	}{
		"admission controller not started without TLS": {
			request: func(t *testing.T, baseURL string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					baseURL+"/",
					nil,
				)
				require.NoError(t, err)

				return req
			},
			assert: func(t *testing.T, err error, _ *http.Response) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "connection refused")
			},
		},
		"/validate-ruleset endpoint is exposed": {
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, baseURL string) *http.Request {
				t.Helper()

				data, err := json.Marshal(admissionv1.AdmissionReview{
					TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
					Request: &admissionv1.AdmissionRequest{
						UID:       "ce409862-eae0-4704-b7d5-46634efdaf9b",
						Namespace: "test",
						Name:      "test-rules",
						Operation: admissionv1.Create,
						Kind: metav1.GroupVersionKind{
							Group:   v1beta1.GroupVersion.Group,
							Version: v1beta1.GroupVersion.Version,
							Kind:    "FooBar",
						},
					},
				})
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					baseURL+"/validate-ruleset",
					bytes.NewReader(data),
				)
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, err error, resp *http.Response) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err = json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.False(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusBadRequest, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "failed parsing RuleSet")
				assert.Contains(t, status.Reason, "invalid Kind")
			},
		},
		"/convert-rulesets endpoint is exposed": {
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, baseURL string) *http.Request {
				t.Helper()

				reqUID := types.UID("ce409862-eae0-4704-b7d5-46634efdaf9b")

				data, err := json.Marshal(apiextv1.ConversionReview{
					TypeMeta: metav1.TypeMeta{Kind: "ConversionReview", APIVersion: "apiextensions.k8s.io/v1"},
					Request: &apiextv1.ConversionRequest{
						UID:               reqUID,
						DesiredAPIVersion: "foobar",
						Objects:           []runtime.RawExtension{},
					},
				})
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					baseURL+"/convert-rulesets",
					bytes.NewReader(data),
				)
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, err error, resp *http.Response) {
				t.Helper()

				reqUID := types.UID("ce409862-eae0-4704-b7d5-46634efdaf9b")

				require.NoError(t, err)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp apiextv1.ConversionReview
				err = json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response

				require.NotNil(t, vResp)
				assert.Equal(t, reqUID, vResp.UID)
				assert.Empty(t, vResp.ConvertedObjects)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusBadRequest, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "no objects to convert")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			listeningAddress = fmt.Sprintf("127.0.0.1:%d", port)

			controller := New(tc.tls, log.Logger, "", mocks.NewFactoryMock(t))
			baseURL := fmt.Sprintf("%s://%s",
				x.IfThenElse(tc.tls != nil, "https", "http"),
				listeningAddress,
			)
			client := x.IfThenElse(tc.tls != nil, tlsClient, notTLSClient)

			err = controller.Start(t.Context())
			require.NoError(t, err)

			time.Sleep(20 * time.Millisecond)

			defer controller.Stop(t.Context())

			// WHEN
			resp, err := client.Do(tc.request(t, baseURL))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assert(t, err, resp)
		})
	}
}
