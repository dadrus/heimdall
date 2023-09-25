package decision2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/request"
)

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		code   int
		setup  func(t *testing.T, rc request.Context)
		assert func(t *testing.T, err error, rec *httptest.ResponseRecorder)
	}{
		{
			uc: "finalize returns error",
			setup: func(t *testing.T, rc request.Context) {
				t.Helper()

				rc.SetPipelineError(errors.New("test error"))
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "only response code is set",
			code: http.StatusNoContent,
			setup: func(t *testing.T, rc request.Context) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Empty(t, rec.Header())
				assert.Equal(t, http.StatusNoContent, rec.Code)
			},
		},
		{
			uc:   "only response code and headers are set",
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc request.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		{
			uc:   "only response code and cookies are set",
			code: http.StatusAccepted,
			setup: func(t *testing.T, rc request.Context) {
				t.Helper()

				rc.AddCookieForUpstream("x-foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "x-foo=bar", rec.Header().Get("Set-Cookie"))
				assert.Equal(t, http.StatusAccepted, rec.Code)
			},
		},
		{
			uc:   "everything is set",
			code: http.StatusOK,
			setup: func(t *testing.T, rc request.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
				rc.AddHeaderForUpstream("X-Bar", "foo")
				rc.AddCookieForUpstream("x-foo", "bar")
				rc.AddCookieForUpstream("x-bar", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 3)
				assert.Equal(t, []string{"x-foo=bar", "x-bar=foo"}, rec.Header().Values("Set-Cookie"))
				assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
				assert.Equal(t, "foo", rec.Header().Get("X-Bar"))
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, "http://heimdall.local/foo", nil)
			require.NoError(t, err)

			reqCtx := newContextFactory(nil, tc.code).Create(rw, req)
			tc.setup(t, reqCtx)

			// WHEN
			err = reqCtx.Finalize(nil)

			// THEN
			tc.assert(t, err, rw)
		})
	}
}
