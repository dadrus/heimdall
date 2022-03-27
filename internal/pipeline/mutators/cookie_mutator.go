package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type cookieMutator struct{}

func NewCookieMutatorFromJSON(rawConfig json.RawMessage) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (cookieMutator) WithConfig(config json.RawMessage) (interfaces.Mutator, error) {
	return nil, nil
}
