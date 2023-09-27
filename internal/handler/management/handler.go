package management

import (
	"net/http"

	"github.com/go-http-utils/etag"
	"github.com/goccy/go-json"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func newManagementHandler(signer heimdall.JWTSigner, eh errorhandler.ErrorHandler) http.Handler {
	mh := &handler{
		s:  signer,
		eh: eh,
	}

	mux := http.NewServeMux()

	mux.Handle(EndpointHealth,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(http.HandlerFunc(mh.health)))
	mux.Handle(EndpointJWKS,
		alice.New(methodfilter.New(http.MethodGet)).
			Then(etag.Handler(http.HandlerFunc(mh.jwks), false)))

	return mux
}

type handler struct {
	s  heimdall.JWTSigner
	eh errorhandler.ErrorHandler
}

// jwks implements an endpoint returning JWKS objects according to
// https://datatracker.ietf.org/doc/html/rfc7517
func (h *handler) jwks(rw http.ResponseWriter, req *http.Request) {
	res, err := json.Marshal(jose.JSONWebKeySet{Keys: h.s.Keys()})
	if err != nil {
		zerolog.Ctx(req.Context()).Error().Err(err).Msg("Failed to marshal json web key set object")
		h.eh.HandleError(rw, req, err)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(res)
}

func (h *handler) health(rw http.ResponseWriter, req *http.Request) {
	type status struct {
		Status string `json:"status"`
	}

	res, err := json.Marshal(status{Status: "ok"})
	if err != nil {
		zerolog.Ctx(req.Context()).Error().Err(err).Msg("Failed to marshal status object")
		h.eh.HandleError(rw, req, err)

		return
	}

	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(res)
}
