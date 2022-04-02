package mutators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type headerMutator struct{}

func NewHeaderMutator(rawConfig map[string]any) (headerMutator, error) {
	return headerMutator{}, nil
}

func (headerMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (headerMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
