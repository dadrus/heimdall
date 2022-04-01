package httpx

import (
	"net/http"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/dadrus/heimdall/internal/x"
)

type TracingRoundTripper struct {
	Next       http.RoundTripper
	TargetName string
}

func (d *TracingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !opentracing.IsGlobalTracerRegistered() {
		return d.Next.RoundTrip(req)
	}

	req, ht := nethttp.TraceRequest(opentracing.GlobalTracer(), req,
		nethttp.OperationName(d.operationName(req)),
		nethttp.ClientSpanObserver(func(span opentracing.Span, r *http.Request) {
			ext.SpanKindRPCClient.Set(span)
		}))
	defer ht.Finish()

	return d.Next.RoundTrip(req)
}

func (d *TracingRoundTripper) operationName(r *http.Request) string {
	return x.IfThenElse(len(d.TargetName) != 0, d.TargetName+" ", "") + r.URL.Path
}
