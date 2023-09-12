package httpx

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type traceRoundTripper struct {
	t http.RoundTripper
}

func NewTraceRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return &traceRoundTripper{t: rt}
}

func (t *traceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	logger := zerolog.Ctx(req.Context())
	if logger.GetLevel() != zerolog.TraceLevel {
		return t.t.RoundTrip(req)
	}

	contentType := req.Header.Get("Content-Type")
	// don't dump the body if content type is some sort of stream
	dump, err := httputil.DumpRequestOut(req,
		req.ContentLength != 0 &&
			!strings.Contains(contentType, "stream") &&
			!strings.Contains(contentType, "application/x-ndjson"))
	if err != nil {
		logger.Trace().Err(err).Msg("Failed dumping out request")
	} else {
		if req.Proto == "HTTP/2.0" {
			logger.Trace().Msg("Used HTTP protocol is HTTP/2.0, even the dump shows HTTP/1.1.")
		}
		logger.Trace().Msg("Outbound Request: \n" + stringx.ToString(dump))
	}

	resp, err := t.t.RoundTrip(req)
	if err != nil {
		logger.Trace().Err(err).Msg("Failed sending request")

		return nil, err
	}

	contentType = resp.Header.Get("Content-Type")
	// don't dump the body if content type is some sort of stream
	dump, err = httputil.DumpResponse(resp,
		resp.ContentLength != 0 &&
			!strings.Contains(contentType, "stream") &&
			!strings.Contains(contentType, "application/x-ndjson"))
	if err != nil {
		logger.Trace().Err(err).Msg("Failed dumping response")
	} else {
		logger.Trace().Msg("Inbound Response: \n" + stringx.ToString(dump))
	}

	return resp, err
}
