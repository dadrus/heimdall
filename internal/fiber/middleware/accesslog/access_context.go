package accesslog

import "context"

type ctxKey struct{}

type accessContext struct {
	err     error
	subject string
}

func AddError(ctx context.Context, err error) {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		c.err = err
	}
}

func AddSubject(ctx context.Context, subject string) {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		c.subject = subject
	}
}
