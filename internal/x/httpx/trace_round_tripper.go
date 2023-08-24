package httpx

import (
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type TraceRoundTripper struct {
	Transport http.RoundTripper
}

func (t *TraceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	logger := zerolog.Ctx(req.Context())

	if logger.GetLevel() == zerolog.TraceLevel {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			logger.Trace().Err(err).Msg("Failed to dump request")
		} else {
			logger.Trace().Msg("Request: \n" + stringx.ToString(dump))
		}
	}

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		logger.Trace().Err(err).Msg("Failed sending request")

		return nil, err
	}

	if logger.GetLevel() == zerolog.TraceLevel {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			logger.Trace().Err(err).Msg("Failed to dump response")
		} else {
			logger.Trace().Msg("Response: \n" + stringx.ToString(dump))
		}
	}

	return resp, err
}
