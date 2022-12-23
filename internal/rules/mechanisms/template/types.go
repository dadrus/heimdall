package template

import (
	"net/url"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type data struct {
	Request *Request
	Subject *subject.Subject
}

type Request struct {
	ctx heimdall.Context

	Method   string
	URL      *url.URL
	ClientIP []string
}

func (r *Request) Header(name string) string { return r.ctx.RequestHeader(name) }
func (r *Request) Cookie(name string) string { return r.ctx.RequestCookie(name) }

func WrapRequest(ctx heimdall.Context) *Request {
	return &Request{
		ctx:      ctx,
		Method:   ctx.RequestMethod(),
		URL:      ctx.RequestURL(),
		ClientIP: ctx.RequestClientIPs(),
	}
}
