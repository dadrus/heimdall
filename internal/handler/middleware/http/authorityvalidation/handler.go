package authorityvalidation

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

// New returns a middleware that rejects requests with a syntactically invalid
// Host header (authority value) with 400 Bad Request.
func New() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !httpx.IsValidAuthority(r.Host) {
				http.Error(w, "Bad Request", http.StatusBadRequest)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

