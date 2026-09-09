package decision

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

func TestCommitterCommit(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers http.Header
		code    int
		setup   func(t *testing.T, rc requestcontext.Context)
		assert  func(t *testing.T, err error, rec *httptest.ResponseRecorder)
	}{
		"only response code is set": {
			code: http.StatusNoContent,
			setup: func(t *testing.T, _ requestcontext.Context) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Empty(t, rec.Header())
				assert.Equal(t, http.StatusNoContent, rec.Code)
			},
		},
		"explicit header mutation is returned": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().AddHeader("X-Foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"bar"}, rec.Header().Values("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"multiple values of explicit header mutation are returned": {
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)

				upstreamRequest := rc.UpstreamRequest()
				upstreamRequest.AddHeader("X-Foo", "bar")
				upstreamRequest.AddHeader("X-Foo", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.ElementsMatch(t, []string{"bar", "foo"}, rec.Header().Values("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		"unchanged request headers are not returned": {
			headers: http.Header{
				"X-Unchanged": []string{"foo"},
				"X-Replaced":  []string{"old"},
			},
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)

				upstreamRequest := rc.UpstreamRequest()
				upstreamRequest.SetHeader("X-Replaced", "new")
				upstreamRequest.SetHeader("X-New", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, rec.Header(), 2)
				assert.Empty(t, rec.Header().Values("X-Unchanged"))
				assert.Equal(t, "new", rec.Header().Get("X-Replaced"))
				assert.Equal(t, "bar", rec.Header().Get("X-New"))
			},
		},
		"cookie mutation returns complete effective Cookie header": {
			headers: http.Header{
				"Cookie": []string{"existing=foo"},
			},
			code: http.StatusAccepted,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().SetCookie("x-foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "existing=foo; x-foo=bar", rec.Header().Get("Cookie"))
				assert.Equal(t, http.StatusAccepted, rec.Code)
			},
		},
		"Host mutation is returned as regular header mutation": {
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.PrepareUpstreamView(nil)
				rc.UpstreamRequest().SetHeader("Host", "upstream.example")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "upstream.example", rec.Header().Get("Host"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://heimdall.local/foo",
				nil,
			)
			require.NoError(t, err)

			if tc.headers != nil {
				req.Header = tc.headers.Clone()
			}

			cf := newContextFactory()
			reqCtx := cf.Create(req)

			defer cf.Destroy(reqCtx)

			tc.setup(t, reqCtx)

			cmt := newCommitter(tc.code)

			// WHEN
			_, err = cmt.Commit(rw, reqCtx)

			// THEN
			tc.assert(t, err, rw)
		})
	}
}
