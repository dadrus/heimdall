package pipeline

import "context"

type Authorizer interface {
	Authorize(context.Context, *SubjectContext) error
}
