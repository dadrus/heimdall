package methodfilter

import "net/http"

func New(method string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Method != method {
				rw.WriteHeader(http.StatusMethodNotAllowed)

				return
			}

			next.ServeHTTP(rw, req)
		})
	}
}
