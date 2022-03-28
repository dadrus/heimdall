package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jwtMutator struct{}

func NewJWTMutatorFromJSON(rawConfig json.RawMessage) (jwtMutator, error) {
	return jwtMutator{}, nil
}

func (jwtMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (jwtMutator) WithConfig(config json.RawMessage) (handler.Mutator, error) {
	return nil, nil
}
