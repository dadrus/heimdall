package requestlimit

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	limit "github.com/dadrus/heimdall/internal/handler/middleware/requestlimit"
	"github.com/dadrus/heimdall/internal/pipeline"
)

func New(maxInFlight int, eh errorhandler.ErrorHandler) func(http.Handler) http.Handler {
	if maxInFlight == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limiter := limit.New(maxInFlight)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if !limiter.TryAcquire() {
				eh.HandleError(rw, req, pipeline.ErrTooManyRequests)

				return
			}

			defer limiter.Release()

			next.ServeHTTP(rw, req)
		})
	}
}
