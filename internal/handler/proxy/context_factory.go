package proxy

import (
	"net/http"
	"sync"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

type contextFactory struct {
	pool *sync.Pool
}

func newContextFactory() *contextFactory {
	return &contextFactory{
		pool: &sync.Pool{
			New: func() any {
				return &requestContext{
					NetHTTPRequestContext: requestcontext.New(),
				}
			},
		},
	}
}

func (cf *contextFactory) Create(req *http.Request) *requestContext {
	rc := cf.pool.Get().(*requestContext) //nolint:forcetypeassert
	rc.Init(req)

	return rc
}

func (cf *contextFactory) Destroy(rc *requestContext) {
	rc.Reset()
	cf.pool.Put(rc)
}
