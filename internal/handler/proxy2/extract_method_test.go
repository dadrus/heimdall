package proxy2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractMethod(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		expect string
		modify func(t *testing.T, header http.Header)
	}{
		{
			"from header",
			http.MethodPatch,
			func(t *testing.T, header http.Header) {
				t.Helper()

				header.Set("X-Forwarded-Method", http.MethodPatch)
			},
		},
		{
			"from request",
			http.MethodDelete,
			func(t *testing.T, header http.Header) { t.Helper() },
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodDelete, "/foo", nil)
			tc.modify(t, req.Header)

			// WHEN
			method := extractMethod(req)

			// THEN
			assert.Equal(t, tc.expect, method)
		})
	}
}
