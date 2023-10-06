package decision

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func newContextFactory(
	signer heimdall.JWTSigner,
	responseCode int,
) requestcontext.ContextFactory {
	return requestcontext.FactoryFunc(func(rw http.ResponseWriter, req *http.Request) requestcontext.Context {
		return &requestContext{
			RequestContext: requestcontext.New(signer, req),
			responseCode:   responseCode,
			rw:             rw,
		}
	})
}

type requestContext struct {
	*requestcontext.RequestContext

	rw           http.ResponseWriter
	responseCode int
}

func (r *requestContext) Finalize(_ rule.Backend) error {
	if err := r.PipelineError(); err != nil {
		return err
	}

	zerolog.Ctx(r.AppContext()).Debug().Msg("Creating response")

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
