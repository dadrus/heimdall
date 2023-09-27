package passthrough

import "net/http"

func New(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { next.ServeHTTP(rw, req) })
}
