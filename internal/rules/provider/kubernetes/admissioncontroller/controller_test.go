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

package admissioncontroller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dadrus/heimdall/internal/config"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
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

	authClass := "test"

	reviewReq := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
		Request: &admissionv1.AdmissionRequest{
			UID:             "ce409862-eae0-4704-b7d5-46634efdaf9b",
			Namespace:       "test",
			Name:            "test-rules",
			Operation:       admissionv1.Create,
			Kind:            metav1.GroupVersionKind{Group: v1alpha4.GroupName, Version: v1alpha4.GroupVersion, Kind: "RuleSet"},
			Resource:        metav1.GroupVersionResource{Group: v1alpha4.GroupName, Version: v1alpha4.GroupVersion, Resource: "rulesets"},
			RequestKind:     &metav1.GroupVersionKind{Group: v1alpha4.GroupName, Version: v1alpha4.GroupVersion, Kind: "RuleSet"},
			RequestResource: &metav1.GroupVersionResource{Group: v1alpha4.GroupName, Version: v1alpha4.GroupVersion, Resource: "rulesets"},
		},
	}

	for _, tc := range []struct {
		uc               string
		tls              *config.TLS
		request          func(t *testing.T, URL string) *http.Request
		setupRuleFactory func(t *testing.T, factory *mocks.FactoryMock)
		assert           func(t *testing.T, err error, resp *http.Response)
	}{
		{
			uc: "admission controller not started",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, URL, nil)
				require.NoError(t, err)

				return req
			},
			assert: func(t *testing.T, err error, _ *http.Response) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "connection refused")
			},
		},
		{
			uc:  "unsupported review request kind",
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				reviewReq.Request.Kind.Kind = "FooBar"

				data, err := json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, URL, bytes.NewReader(data))
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
				assert.Contains(t, status.Reason, "only rule sets")
				require.NotNil(t, status.Details)
				require.Len(t, status.Details.Causes, 1)
				assert.Contains(t, status.Details.Causes[0].Message, "only rule sets")
			},
		},
		{
			uc:  "RuleSet filtered",
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha4.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha4.GroupName, v1alpha4.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha4.RuleSetSpec{AuthClassName: "foo"},
				}
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, URL, bytes.NewReader(data))
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
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Contains(t, status.Message, "RuleSet ignored")
			},
		},
		{
			uc:  "RuleSet validation fails",
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha4.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha4.GroupName, v1alpha4.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha4.RuleSetSpec{
						AuthClassName: authClass,
						Rules: []config2.Rule{
							{
								ID: "test",
								Matcher: config2.Matcher{
									Routes:  []config2.Route{{Path: "/foo.bar"}},
									Scheme:  "http",
									Methods: []string{http.MethodGet},
								},
								Backend: &config2.Backend{
									Host: "baz",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupRuleFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().CreateRule("1alpha4", mock.Anything, mock.Anything).
					Once().Return(nil, errors.New("Test error"))
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
				assert.Equal(t, http.StatusForbidden, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "RuleSet invalid")
				assert.Contains(t, status.Reason, "Test error")
				require.NotNil(t, status.Details)
				require.Len(t, status.Details.Causes, 1)
				assert.Contains(t, status.Details.Causes[0].Message, "Test error")
			},
		},
		{
			uc:  "successful RuleSet validation",
			tls: &config.TLS{KeyStore: config.KeyStore{Path: pemFile.Name()}},
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha4.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha4.GroupName, v1alpha4.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha4.RuleSetSpec{
						AuthClassName: authClass,
						Rules: []config2.Rule{
							{
								ID: "test",
								Matcher: config2.Matcher{
									Routes:  []config2.Route{{Path: "/foo.bar"}},
									Scheme:  "http",
									Methods: []string{http.MethodGet},
								},
								Backend: &config2.Backend{
									Host: "baz",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupRuleFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().CreateRule("1alpha4", mock.Anything, mock.Anything).
					Once().Return(nil, nil)
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
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Contains(t, status.Message, "RuleSet valid")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			reviewReq.Request.Kind.Kind = "RuleSet"
			reviewReq.Request.Object.Raw = nil

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)

			listeningAddress = fmt.Sprintf("127.0.0.1:%d", port)

			setupMock := x.IfThenElse(
				tc.setupRuleFactory != nil,
				tc.setupRuleFactory,
				func(t *testing.T, _ *mocks.FactoryMock) { t.Helper() },
			)

			rf := mocks.NewFactoryMock(t)
			setupMock(t, rf)

			controller := New(tc.tls, log.Logger, authClass, rf)
			serviceAddress := fmt.Sprintf("%s://%s/validate-ruleset",
				x.IfThenElse(tc.tls != nil, "https", "http"),
				listeningAddress,
			)
			client := x.IfThenElse(tc.tls != nil, tlsClient, notTLSClient)

			err = controller.Start(t.Context())
			require.NoError(t, err)

			time.Sleep(20 * time.Millisecond)

			defer controller.Stop(t.Context())

			// WHEN
			resp, err := client.Do(tc.request(t, serviceAddress))

			// THEN
			if err == nil {
				defer resp.Body.Close()
			}

			tc.assert(t, err, resp)
		})
	}
}
