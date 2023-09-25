package decision2

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func newContextFactory(signer heimdall.JWTSigner, responseCode int) request.ContextFactory {
	return request.FactoryFunc(func(rw http.ResponseWriter, req *http.Request) request.Context {
		return &requestContext{
			RequestContext: request.NewRequestContext(signer, req),
			responseCode:   responseCode,
			rw:             rw,
		}
	})
}

type requestContext struct {
	*request.RequestContext

	rw           http.ResponseWriter
	responseCode int
}

func (r *requestContext) Finalize(_ rule.Backend) error {
	logger := zerolog.Ctx(r.AppContext())
	logger.Debug().Msg("Finalizing request")

	if err := r.PipelineError(); err != nil {
		return err
	}

	uh := r.UpstreamHeaders()
	for k := range uh {
		r.rw.Header().Set(k, uh.Get(k))
	}

	for k, v := range r.UpstreamCookies() {
		http.SetCookie(r.rw, &http.Cookie{Name: k, Value: v})
	}

	r.rw.WriteHeader(r.responseCode)

	return nil
}
