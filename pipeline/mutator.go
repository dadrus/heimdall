package pipeline

import "context"

type Mutator interface {
	Mutate(context.Context, *SubjectContext) error
}
