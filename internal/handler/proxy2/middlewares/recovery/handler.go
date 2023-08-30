package recovery

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func New(eh errorhandler.ErrorHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					zerolog.Ctx(req.Context()).Error().Msg(fmt.Sprintf("%v\n%s", rec, stringx.ToString(debug.Stack())))

					err, ok := rec.(error)
					if ok {
						err = errorchain.NewWithMessage(heimdall.ErrInternal, "runtime error occurred").
							CausedBy(err)
					} else {
						// nolint: goerr113
						err = errorchain.NewWithMessage(heimdall.ErrInternal, "runtime error occurred").
							CausedBy(fmt.Errorf("%v", rec))
					}

					eh.HandleError(rw, req, err)
				}
			}()

			next.ServeHTTP(rw, req)
		})
	}
}
