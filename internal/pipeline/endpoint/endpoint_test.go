package endpoint

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/tracing"
)

func TestEndpointValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		endpoint Endpoint
		assert   func(t *testing.T, err error)
	}{
		{
			uc:       "endpoint without required URL attribute",
			endpoint: Endpoint{Method: "GET"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "requires url")
			},
		},
		{
			uc:       "endpoint with required URL attribute",
			endpoint: Endpoint{URL: "http://foo.bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// THEN
			tc.assert(t, tc.endpoint.Validate())
		})
	}
}

func TestEndpointCreateClient(t *testing.T) {
	t.Parallel()

	peerName := "foobar"

	for _, tc := range []struct {
		uc       string
		endpoint Endpoint
		assert   func(t *testing.T, client *http.Client)
	}{
		{
			uc:       "for endpoint without configured retry policy",
			endpoint: Endpoint{URL: "http://foo.bar"},
			assert: func(t *testing.T, client *http.Client) {
				t.Helper()

				rt, ok := client.Transport.(*tracing.RoundTripper)
				require.True(t, ok)

				assert.Equal(t, peerName, rt.TargetName)
				assert.IsType(t, &nethttp.Transport{}, rt.Next)
			},
		},
		{
			uc: "for endpoint with configured retry policy",
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

				rt, ok := rrt.Next.(*tracing.RoundTripper)
				require.True(t, ok)
				assert.Equal(t, peerName, rt.TargetName)
				assert.IsType(t, &nethttp.Transport{}, rt.Next)
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

	for _, tc := range []struct {
		uc       string
		endpoint Endpoint
		body     []byte
		assert   func(t *testing.T, request *http.Request, err error)
	}{
		{
			uc:       "with only URL set",
			endpoint: Endpoint{URL: "http://foo.bar"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				reqURL, err := url.Parse("http://foo.bar")
				require.NoError(t, err)

				assert.Equal(t, "POST", request.Method)
				assert.Equal(t, reqURL, request.URL)
				assert.Nil(t, request.Body)
				assert.Len(t, request.Header, 0)
			},
		},
		{
			uc:       "with only URL and valid method set",
			endpoint: Endpoint{URL: "http://test.org", Method: "GET"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				reqURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				assert.Equal(t, "GET", request.Method)
				assert.Equal(t, reqURL, request.URL)
				assert.Nil(t, request.Body)
				assert.Len(t, request.Header, 0)
			},
		},
		{
			uc:       "with invalid URL",
			endpoint: Endpoint{URL: "://test.org"},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "request instance")
			},
		},
		{
			uc:       "with only URL, method and body set",
			endpoint: Endpoint{URL: "http://test.org", Method: "GET"},
			body:     []byte(`foobar`),
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				reqURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				assert.Equal(t, "GET", request.Method)
				assert.Equal(t, reqURL, request.URL)
				assert.NotNil(t, request.Body)
				assert.Len(t, request.Header, 0)
			},
		},
		{
			uc: "with auth strategy, applied successfully",
			endpoint: Endpoint{
				URL:          "http://test.org",
				AuthStrategy: &BasicAuthStrategy{User: "foo", Password: "bar"},
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				reqURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				assert.Equal(t, "POST", request.Method)
				assert.Equal(t, reqURL, request.URL)
				assert.Len(t, request.Header, 1)
				assert.NotEmpty(t, request.Header.Get("Authorization"))
				user, pass, _ := request.BasicAuth()
				assert.Equal(t, "foo", user)
				assert.Equal(t, "bar", pass)
			},
		},
		{
			uc: "with failing auth strategy",
			endpoint: Endpoint{
				URL:          "http://test.org",
				AuthStrategy: &APIKeyStrategy{In: "foo", Name: "bar", Value: "baz"},
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to authenticate request")
			},
		},
		{
			uc: "with auth strategy and additional header",
			endpoint: Endpoint{
				URL:          "http://test.org",
				Method:       "PATCH",
				AuthStrategy: &BasicAuthStrategy{User: "foo", Password: "bar"},
				Headers:      map[string]string{"Foo-Bar": "baz"},
			},
			assert: func(t *testing.T, request *http.Request, err error) {
				t.Helper()

				require.NoError(t, err)

				reqURL, err := url.Parse("http://test.org")
				require.NoError(t, err)

				assert.Equal(t, "PATCH", request.Method)
				assert.Equal(t, reqURL, request.URL)

				assert.Len(t, request.Header, 2)

				assert.NotEmpty(t, request.Header.Get("Authorization"))
				user, pass, _ := request.BasicAuth()
				assert.Equal(t, "foo", user)
				assert.Equal(t, "bar", pass)

				assert.Equal(t, "baz", request.Header.Get("Foo-Bar"))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			var body io.Reader
			if tc.body != nil {
				body = bytes.NewReader(tc.body)
			}

			// WHEN
			req, err := tc.endpoint.CreateRequest(context.Background(), body, nil)

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
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "request instance")
			},
		},
		{
			uc:       "with dns error",
			endpoint: Endpoint{URL: "http://heimdall.test.local"},
			assert: func(t *testing.T, response []byte, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
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
				assert.ErrorIs(t, err, heimdall.ErrCommunication)
				assert.Contains(t, err.Error(), "unexpected response code")
			},
		},
		{
			uc: "successful",
			endpoint: Endpoint{
				URL:          srv.URL,
				Method:       "PATCH",
				AuthStrategy: &BasicAuthStrategy{User: "foo", Password: "bar"},
				Headers:      map[string]string{"Foo-Bar": "baz"},
			},
			body: []byte(`{"hello":"world"}`),
			instructServer: func(t *testing.T) {
				t.Helper()

				serverResponse = []byte("hello from srv")

				checkRequest = func(request *http.Request) {
					t.Helper()

					assert.Equal(t, "PATCH", request.Method)

					assert.NotEmpty(t, request.Header)

					assert.NotEmpty(t, request.Header.Get("Authorization"))
					user, pass, _ := request.BasicAuth()
					assert.Equal(t, "foo", user)
					assert.Equal(t, "bar", pass)

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
	e3 := Endpoint{URL: "foo.bar", Method: "FOO", AuthStrategy: &BasicAuthStrategy{User: "user", Password: "pass"}}
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
