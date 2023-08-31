package _interface

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
)

//go:generate mockery --name RequestContext --structname RequestContextMock

type RequestContext interface {
	heimdall.Context

	Finalize(targetURL *url.URL)
	Error(err error)
	UpstreamURLRequired() bool
}
