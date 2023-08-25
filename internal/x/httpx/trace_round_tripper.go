package httpx

import (
	"net/http"
	"net/http/httputil"

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

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		logger.Trace().Err(err).Msg("Failed to dump request")
	} else {
		logger.Trace().Msg("Request: \n" + stringx.ToString(dump))
	}

	resp, err := t.t.RoundTrip(req)
	if err != nil {
		logger.Trace().Err(err).Msg("Failed sending request")

		return nil, err
	}

	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		logger.Trace().Err(err).Msg("Failed to dump response")
	} else {
		logger.Trace().Msg("Response: \n" + stringx.ToString(dump))
	}

	return resp, err
}
