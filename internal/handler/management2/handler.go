package management2

import (
	"net/http"

	"github.com/go-http-utils/etag"
	"github.com/justinas/alice"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func newManagementHandler(signer heimdall.JWTSigner) http.Handler {
	mux := http.NewServeMux()

	mux.Handle(EndpointHealth, alice.New(MethodFilter(http.MethodGet)).Then(health()))
	mux.Handle(EndpointJWKS, alice.New(MethodFilter(http.MethodGet)).Then(etag.Handler(jwks(signer), false)))

	return mux
}

func MethodFilter(method string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Method != method {
				rw.WriteHeader(http.StatusMethodNotAllowed)

				return
			}

			next.ServeHTTP(rw, req)
		})
	}
}
