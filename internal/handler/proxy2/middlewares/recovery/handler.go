package recovery

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

func New() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			logger := zerolog.Ctx(req.Context())

			defer func() {
				if rec := recover(); rec != nil {
					if err, ok := rec.(error); !ok {
						logger.Error().
							Err(err).
							Str("_stack", stringx.ToString(debug.Stack())).
							Msg("Panic caught")
					} else {
						logger.Error().
							Str("_error", fmt.Sprintf("%v", rec)).
							Str("_stack", stringx.ToString(debug.Stack())).
							Msg("Panic caught")
					}
				}

				rw.WriteHeader(http.StatusInternalServerError)
			}()

			next.ServeHTTP(rw, req)
		})
	}
}
