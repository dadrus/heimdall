package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type jwtMutator struct{}

func NewJWTMutator(rawConfig map[string]any) (jwtMutator, error) {
	return jwtMutator{}, nil
}

func (jwtMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (jwtMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
