package methodfilter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter/mocks"
)

//go:generate mockery --srcpkg "net/http" --name Handler --structname HandlerMock

func TestHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		requestMethod string
		filterMethod  string
		setupNext     func(t *testing.T, next *mocks.HandlerMock)
		assert        func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		{
			uc:            "method accepted",
			requestMethod: http.MethodDelete,
			filterMethod:  http.MethodDelete,
			setupNext: func(t *testing.T, next *mocks.HandlerMock) {
				t.Helper()

				next.EXPECT().ServeHTTP(mock.Anything, mock.Anything)
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()
			},
		},
		{
			uc:            "method not allowed",
			requestMethod: http.MethodDelete,
			filterMethod:  http.MethodGet,
			setupNext: func(t *testing.T, next *mocks.HandlerMock) {
				t.Helper()
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			next := mocks.NewHandlerMock(t)
			tc.setupNext(t, next)

			handler := New(tc.filterMethod)
			rw := httptest.NewRecorder()

			// WHEN
			handler(next).ServeHTTP(rw, httptest.NewRequest(tc.requestMethod, "http://heimdall.local/foo", nil))

			// THEN
			tc.assert(t, rw)
		})
	}
}
