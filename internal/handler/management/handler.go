package management

import (
	"net/http"

	"github.com/go-http-utils/etag"
	"github.com/justinas/alice"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func newManagementHandler(signer heimdall.JWTSigner) http.Handler {
	mux := http.NewServeMux()

	mux.Handle(EndpointHealth, alice.New(methodfilter.New(http.MethodGet)).Then(health()))
	mux.Handle(EndpointJWKS, alice.New(methodfilter.New(http.MethodGet)).Then(etag.Handler(jwks(signer), false)))

	return mux
}
