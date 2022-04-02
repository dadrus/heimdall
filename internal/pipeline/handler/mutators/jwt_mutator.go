package mutators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jwtMutator struct{}

func NewJWTMutator(rawConfig map[string]any) (jwtMutator, error) {
	return jwtMutator{}, nil
}

func (jwtMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (jwtMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
