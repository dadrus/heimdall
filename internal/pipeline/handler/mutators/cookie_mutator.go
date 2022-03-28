package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type cookieMutator struct{}

func NewCookieMutatorFromJSON(rawConfig json.RawMessage) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (cookieMutator) WithConfig(config []byte) (handler.Mutator, error) {
	return nil, nil
}
