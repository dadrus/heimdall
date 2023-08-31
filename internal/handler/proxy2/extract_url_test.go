package proxy2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		configureRequest func(t *testing.T, req *http.Request)
		assert           func(t *testing.T, extracted *url.URL)
	}{
		{
			uc: "X-Forwarded-Proto set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Proto", "https")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "https", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/test", extracted.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Host set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Host", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "foobar", extracted.Host)
				assert.Equal(t, "/test", extracted.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Path set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Path", "foobar")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "foobar", extracted.Path)
				assert.Equal(t, url.Values{"foo": []string{"bar"}}, extracted.Query())
			},
		},
		{
			uc: "X-Forwarded-Uri set",
			configureRequest: func(t *testing.T, req *http.Request) {
				t.Helper()

				req.Header.Set("X-Forwarded-Uri", "/bar?bar=foo")
				req.URL.RawQuery = url.Values{"foo": []string{"bar"}}.Encode()
			},
			assert: func(t *testing.T, extracted *url.URL) {
				t.Helper()

				assert.Equal(t, "http", extracted.Scheme)
				assert.Equal(t, "heimdall.test.local", extracted.Host)
				assert.Equal(t, "/bar", extracted.Path)
				assert.Equal(t, url.Values{"bar": []string{"foo"}}, extracted.Query())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodGet, "http://heimdall.test.local/test", nil)

			tc.configureRequest(t, req)

			// WHEN
			extracted := extractURL(req)

			// THEN
			tc.assert(t, extracted)
		})
	}
}
