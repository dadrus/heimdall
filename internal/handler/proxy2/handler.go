package proxy2

import (
	"net/http"

	"github.com/rs/zerolog"

	_interface "github.com/dadrus/heimdall/internal/handler/proxy2/interface"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type handler struct {
	re  rule.Executor
	rcf _interface.RequestContextFactory
}

func newHandler(rcf _interface.RequestContextFactory, re rule.Executor) http.Handler {
	return &handler{rcf: rcf, re: re}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rc := h.rcf.Create(rw, req)
	rcr := rc.Request()

	//nolint:contextcheck
	zerolog.Ctx(rc.AppContext()).Debug().
		Str("_method", rcr.Method).
		Str("_url", rcr.URL.String()).
		Msg("Proxy endpoint called")

	targetURL, err := h.re.Execute(rc, true)
	if err != nil {
		rc.Error(err)

		return
	}

	rc.Finalize(targetURL)
}
