package httpx

import (
	"net/http"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

type TracingRoundTripper struct {
	Next       http.RoundTripper
	TargetName string
}

func (d *TracingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if !opentracing.IsGlobalTracerRegistered() {
		return d.Next.RoundTrip(r)
	}

	req, ht := nethttp.TraceRequest(opentracing.GlobalTracer(), r,
		nethttp.OperationName(d.operationName(r)),
		nethttp.ClientSpanObserver(func(span opentracing.Span, r *http.Request) {
			ext.SpanKindRPCClient.Set(span)
		}))
	defer ht.Finish()

	return d.Next.RoundTrip(req)
}

func (d *TracingRoundTripper) operationName(r *http.Request) string {
	opName := ""
	if len(d.TargetName) != 0 {
		opName = d.TargetName + " "
	}
	opName += r.URL.Path
	return opName
}
