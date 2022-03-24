package pipeline

import "context"

type Hydrator interface {
	Hydrate(context.Context, *SubjectContext) error
}
