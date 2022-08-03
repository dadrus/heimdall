package accesslog

import "context"

type ctxKey struct{}

type Context struct {
	Err     error
	Subject string
}

func Ctx(ctx context.Context) *Context {
	if c, ok := ctx.Value(ctxKey{}).(*Context); ok {
		return c
	}

	// can only happen in tests
	return &Context{}
}
