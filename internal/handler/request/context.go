package request

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
)

//go:generate mockery --name Context --structname ContextMock

type Context interface {
	heimdall.Context

	Finalize(targetURL *url.URL)
	Error(err error)
	UpstreamURLRequired() bool
}
