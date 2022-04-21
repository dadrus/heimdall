package tracing

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/opentracing/opentracing-go"
)

type RoundTripper struct {
	Next       http.RoundTripper
	TargetName string
}

func (d *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !opentracing.IsGlobalTracerRegistered() {
		return d.Next.RoundTrip(req)
	}

	req, ht := nethttp.TraceRequest(opentracing.GlobalTracer(), req,
		nethttp.OperationName(d.operationName(req)))
	defer ht.Finish()

	return d.Next.RoundTrip(req)
}

func (d *RoundTripper) operationName(r *http.Request) string {
	return x.IfThenElse(len(d.TargetName) != 0, d.TargetName+" ", "") + r.URL.Path
}
