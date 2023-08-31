package proxy2

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/request"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type handler struct {
	re  rule.Executor
	rcf request.ContextFactory
}

func newHandler(rcf request.ContextFactory, re rule.Executor) http.Handler {
	return &handler{rcf: rcf, re: re}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rc := h.rcf.Create(rw, req)

	targetURL, err := h.re.Execute(rc, rc.UpstreamURLRequired())
	if err != nil {
		rc.Error(err)

		return
	}

	rc.Finalize(targetURL)
}
