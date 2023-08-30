package proxy2

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type handler struct {
	r  rule.Repository
	s  heimdall.JWTSigner
	t  time.Duration
	eh errorhandler.ErrorHandler
}

func newHandler(
	repo rule.Repository,
	signer heimdall.JWTSigner,
	timeout time.Duration,
	eh errorhandler.ErrorHandler,
) http.Handler {
	return &handler{r: repo, s: signer, t: timeout, eh: eh}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := zerolog.Ctx(ctx)
	reqURL := requestURL(req)
	method := requestMethod(req)

	logger.Debug().
		Str("_method", method).
		Str("_url", reqURL.String()).
		Msg("Proxy endpoint called")

	rul, err := h.r.FindRule(reqURL)
	if err != nil {
		h.eh.HandleError(rw, req, err)

		return
	}

	if !rul.MatchesMethod(method) {
		h.eh.HandleError(rw, req, errorchain.NewWithMessagef(heimdall.ErrMethodNotAllowed,
			"rule (id=%s, src=%s) doesn't match %s method", rul.ID(), rul.SrcID(), method))

		return
	}

	reqCtx := NewRequestContext(rw, req, method, reqURL, h.s)

	mutator, err := rul.Execute(reqCtx)
	if err != nil {
		h.eh.HandleError(rw, req, err)

		return
	}

	targetURL, err := mutator.Mutate(reqURL)
	if err != nil {
		h.eh.HandleError(rw, req, err)

		return
	}

	// context is already part of the reqCtx
	if err = reqCtx.Finalize(targetURL, h.t); err != nil { //nolint:contextcheck
		h.eh.HandleError(rw, req, err)
	}
}
