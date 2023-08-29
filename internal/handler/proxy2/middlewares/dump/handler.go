package dump

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

func New() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			logger := zerolog.Ctx(req.Context())

			if logger.GetLevel() != zerolog.TraceLevel {
				next.ServeHTTP(rw, req)

				return
			}

			if dump, err := httputil.DumpRequest(req, true); err != nil {
				logger.Trace().Msg("Request: \n" + stringx.ToString(dump))
			} else {
				logger.Trace().Err(err).Msg("Failed dumping request")
			}

			httptest.NewRecorder()
			next.ServeHTTP(rw, req)

			// TODO: dump response
		})
	}
}
