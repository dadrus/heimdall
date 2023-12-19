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

package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ybbus/httpretry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/httpcache"
	"github.com/dadrus/heimdall/internal/rules/endpoint/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestEndpointCreateClient(t *testing.T) {
	t.Parallel()

	peerName := "foobar"

	for _, tc := range []struct {
		uc       string
		endpoint Endpoint
		assert   func(t *testing.T, client *http.Client)
	}{
		{
			uc:       "for endpoint without configured retry policy and without http cache",
			endpoint: Endpoint{URL: "http://foo.bar"},
			assert: func(t *testing.T, client *http.Client) {
				t.Helper()

				_, ok := client.Transport.(*otelhttp.Transport)
				require.True(t, ok)
			},
		},
		{
			uc:       "for endpoint without configured retry policy, but with http cache",
			endpoint: Endpoint{URL: "http://foo.bar", HTTPCache: &HTTPCache{Enabled: true}},
			assert: func(t *testing.T, client *http.Client) {
				t.Helper()

				cacheTransport, ok := client.Transport.(*httpcache.RoundTripper)
				require.True(t, ok)
				assert.Equal(t, 0*time.Minute, cacheTransport.DefaultCacheTTL)

				_, ok = cacheTransport.Transport.(*otelhttp.Transport)
				require.True(t, ok)
			},
		},
		{
			uc: "for endpoint with configured retry policy and without http cache",
			endpoint: Endpoint{
				URL:   "http://foo.bar",
				Retry: &Retry{GiveUpAfter: 2 * time.Second, MaxDelay: 10 * time.Second},
			},
			assert: func(t *testing.T, client *http.Client) {
				t.Helper()

				rrt, ok := client.Transport.(*httpretry.RetryRoundtripper)
				require.True(t, ok)
				assert.NotZero(t, rrt.MaxRetryCount)
				assert.NotNil(t, rrt.ShouldRetry)
				assert.NotNil(t, rrt.CalculateBackoff)

				_, ok = rrt.Next.(*otelhttp.Transport)
				require.True(t, ok)
			},
		},
		{
			uc: "for endpoint with configured retry policy and with http cache with default cache ttl",
			endpoint: Endpoint{
				URL:       "http://foo.bar",
				Retry:     &Retry{GiveUpAfter: 2 * time.Second, MaxDelay: 10 * time.Second},
				HTTPCache: &HTTPCache{Enabled: true, DefaultTTL: 15 * time.Minute},
			},
			assert: func(t *testing.T, client *http.Client) {
				t.Helper()

				cacheTransport, ok := client.Transport.(*httpcache.RoundTripper)
				require.True(t, ok)
				assert.Equal(t, 15*time.Minute, cacheTransport.DefaultCacheTTL)

				rrt, ok := cacheTransport.Transport.(*httpretry.RetryRoundtripper)
				require.True(t, ok)
				assert.NotZero(t, rrt.MaxRetryCount)
				assert.NotNil(t, rrt.ShouldRetry)
				assert.NotNil(t, rrt.CalculateBackoff)

				_, ok = rrt.Next.(*otelhttp.Transport)
				require.True(t, ok)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// THEN
			tc.assert(t, tc.endpoint.CreateClient(peerName))
		})
	}
}

func TestEndpointCreateRequest(t *testing.T) {
	t.Parallel()

	renderer := func(values map[string]any) RenderFunc {
		return func(tpl string) (string, error) {
			tmpl, err := template.New("test").Parse(tpl)
			if err != nil {
				return "", err
			}

			var buf bytes.Buffer

			err = tmpl.Execute(&buf, map[string]any{"Values": values})
			if err != nil {
				return "", err
			}

			return buf.String(), nil
		}
	}

	for _, tc := range []struct {
		uc       string
		endpoint Endpoint
		renderer Renderer
		body     []byte
		assert   func(t *testing.T, request *http.Request, err error)
	}{
		{
			uc:       "with only URL set",
			endpoint: Endpoint{URL: "http://foo.bar"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "POST", request.Method)
				assert.Equal(t, "http://foo.bar", request.URL.String())
				assert.Nil(t, request.Body)
				assert.Empty(t, request.Header)
			},
		},
		{
			uc:       "with only URL and valid method set",
			endpoint: Endpoint{URL: "http://test.org", Method: "GET"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "GET", request.Method)
				assert.Equal(t, "http://test.org", request.URL.String())
				assert.Nil(t, request.Body)
				assert.Empty(t, request.Header)
			},
		},
		{
			uc:       "with invalid URL",
			endpoint: Endpoint{URL: "://test.org"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to create a request")
			},
		},
		{
			uc:       "with only URL, method and body set",
			endpoint: Endpoint{URL: "http://test.org", Method: "GET"},
			body:     []byte(`foobar`),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "GET", request.Method)
				assert.Equal(t, "http://test.org", request.URL.String())
				assert.NotNil(t, request.Body)
				assert.Empty(t, request.Header)
			},
		},
		{
			uc: "with auth strategy, applied successfully",
			endpoint: Endpoint{
				URL: "http://test.org",
				AuthStrategy: func() AuthenticationStrategy {
					as := mocks.NewAuthenticationStrategyMock(t)
					as.EXPECT().Apply(
						mock.Anything,
						mock.MatchedBy(func(req *http.Request) bool {
							req.Header.Set("X-Test", "test")

							return true
						}),
					).Return(nil)

					return as
				}(),
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "POST", request.Method)
				assert.Equal(t, "http://test.org", request.URL.String())
				assert.Len(t, request.Header, 1)
				assert.Equal(t, "test", request.Header.Get("X-Test"))
			},
		},
		{
			uc: "with failing auth strategy",
			endpoint: Endpoint{
				URL: "http://test.org",
				AuthStrategy: func() AuthenticationStrategy {
					as := mocks.NewAuthenticationStrategyMock(t)
					as.EXPECT().Apply(mock.Anything, mock.Anything).Return(errors.New("test error"))

					return as
				}(),
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to authenticate request")
			},
		},
		{
			uc: "with auth strategy and additional header",
			endpoint: Endpoint{
				URL:    "http://test.org",
				Method: "PATCH",
				AuthStrategy: func() AuthenticationStrategy {
					as := mocks.NewAuthenticationStrategyMock(t)
					as.EXPECT().Apply(mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
						req.Header.Set("X-Test", "test")

						return true
					})).Return(nil)

					return as
				}(),
				Headers: map[string]string{"Foo-Bar": "baz"},
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "PATCH", request.Method)
				assert.Equal(t, "http://test.org", request.URL.String())

				assert.Len(t, request.Header, 2)
				assert.Equal(t, "test", request.Header.Get("X-Test"))
				assert.Equal(t, "baz", request.Header.Get("Foo-Bar"))
			},
		},
		{
			uc: "with templated url",
			endpoint: Endpoint{
				URL: "http://test.org/{{ .Values.key }}",
			},
			renderer: renderer(map[string]any{"key": "foo"}),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://test.org/foo", request.URL.String())
			},
		},
		{
			uc: "with error while rendering templated url",
			endpoint: Endpoint{
				URL: "http://test.org/{{ .Values.foo }",
			},
			renderer: renderer(nil),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render URL")
			},
		},
		{
			uc: "with templated header",
			endpoint: Endpoint{
				URL: "http://test.org",
				Headers: map[string]string{
					"X-My-Header-1": "{{ .Values.key }}",
					"X-My-Header-2": "bar",
				},
			},
			renderer: renderer(map[string]any{"key": "foo"}),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "http://test.org", request.URL.String())
				assert.Len(t, request.Header, 2)
				assert.Equal(t, "foo", request.Header.Get("X-My-Header-1"))
				assert.Equal(t, "bar", request.Header.Get("X-My-Header-2"))
			},
		},
		{
			uc: "with error while rendering templated header",
			endpoint: Endpoint{
				URL:     "http://test.org",
				Headers: map[string]string{"X-My-Header-1": "{{ .Values.key }"},
			},
			renderer: renderer(nil),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "header value")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var body io.Reader
			if tc.body != nil {
				body = bytes.NewReader(tc.body)
			}

			// WHEN
			req, err := tc.endpoint.CreateRequest(context.Background(), body, tc.renderer)

			// THEN
			tc.assert(t, req, err)
		})
	}
}

func TestEndpointSendRequest(t *testing.T) {
	t.Parallel()

	var (
		statusCode     int
		checkRequest   func(req *http.Request)
		serverResponse []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkRequest(r)

		if serverResponse != nil {
			_, err := w.Write(serverResponse)
			require.NoError(t, err)
		}

		w.WriteHeader(statusCode)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		endpoint       Endpoint
		body           []byte
		instructServer func(t *testing.T)
		assert         func(t *testing.T, response []byte, err error)
	}{
		{
			uc:       "with failing request creation",
			endpoint: Endpoint{URL: "://test.org"},
			assert: func(t *testing.T, response []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to create a request")
			},
		},
		{
			uc:       "with dns error",
			endpoint: Endpoint{URL: "http://heimdall.test.local"},
			assert: func(t *testing.T, response []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "lookup heimdall")
			},
		},
		{
			uc:       "with unexpected response from server",
			endpoint: Endpoint{URL: srv.URL},
			instructServer: func(t *testing.T) {
				t.Helper()

				statusCode = http.StatusBadGateway
			},
			assert: func(t *testing.T, response []byte, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")
			},
		},
		{
			uc: "successful",
			endpoint: Endpoint{
				URL:    srv.URL,
				Method: "PATCH",
				AuthStrategy: func() AuthenticationStrategy {
					as := mocks.NewAuthenticationStrategyMock(t)
					as.EXPECT().Apply(mock.Anything, mock.MatchedBy(func(req *http.Request) bool {
						req.Header.Set("X-Test", "test")

						return true
					})).Return(nil)

					return as
				}(),
				Headers: map[string]string{"Foo-Bar": "baz"},
			},
			body: []byte(`{"hello":"world"}`),
			instructServer: func(t *testing.T) {
				t.Helper()

				serverResponse = []byte("hello from srv")

				checkRequest = func(request *http.Request) {
					t.Helper()

					assert.Equal(t, "PATCH", request.Method)

					assert.NotEmpty(t, request.Header)
					assert.Equal(t, "test", request.Header.Get("X-Test"))
					assert.Equal(t, "baz", request.Header.Get("Foo-Bar"))

					rawData, err := io.ReadAll(request.Body)
					require.NoError(t, err)
					assert.Equal(t, []byte(`{"hello":"world"}`), rawData)
				}
			},
			assert: func(t *testing.T, response []byte, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, []byte("hello from srv"), response)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			//  GIVEN
			statusCode = http.StatusOK
			checkRequest = func(*http.Request) { t.Helper() }

			instructServer := x.IfThenElse(tc.instructServer != nil,
				tc.instructServer,
				func(t *testing.T) { t.Helper() })
			instructServer(t)

			var body io.Reader
			if tc.body != nil {
				body = bytes.NewReader(tc.body)
			}

			// WHEN
			response, err := tc.endpoint.SendRequest(context.Background(), body, nil)

			// THEN
			tc.assert(t, response, err)
		})
	}
}

func TestEndpointHash(t *testing.T) {
	t.Parallel()

	// GIVEN
	e1 := Endpoint{URL: "foo.bar"}
	e2 := Endpoint{URL: "foo.bar", Method: "FOO", Headers: map[string]string{"baz": "foo"}}
	e3 := Endpoint{URL: "foo.bar", Method: "FOO", AuthStrategy: func() AuthenticationStrategy {
		as := mocks.NewAuthenticationStrategyMock(t)
		as.EXPECT().Hash().Return([]byte{1, 2, 3})

		return as
	}()}
	e4 := Endpoint{URL: "foo.bar", Retry: &Retry{GiveUpAfter: 2}}

	// WHEN
	hash1 := e1.Hash()
	hash2 := e2.Hash()
	hash3 := e3.Hash()
	hash4 := e4.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEmpty(t, hash3)
	assert.NotEmpty(t, hash4)

	assert.NotEqual(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
	assert.NotEqual(t, hash1, hash4)
	assert.NotEqual(t, hash2, hash3)
	assert.NotEqual(t, hash2, hash4)
	assert.NotEqual(t, hash3, hash4)
}
