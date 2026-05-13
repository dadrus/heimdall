package pipeline

import "context"

type Pipeline interface {
	Execute(ctx Context, subject Subject) error
	CleanUp(ctx context.Context)
}
