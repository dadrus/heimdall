package proxy2

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler"
	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type handler struct {
	e  rule.Executor
	f  request.ContextFactory
	eh errorhandler.ErrorHandler
}

func newHandler(rcf request.ContextFactory, re rule.Executor, eh errorhandler.ErrorHandler) http.Handler {
	return &handler{f: rcf, eh: eh, e: re}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rc := h.f.Create(rw, req)

	mut, err := h.e.Execute(rc)
	if err != nil {
		h.eh.HandleError(rw, req, err)

		return
	}

	if err = rc.Finalize(mut); err != nil {
		h.eh.HandleError(rw, req, err)
	}
}
