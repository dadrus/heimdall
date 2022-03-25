package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type cookieMutator struct{}

func NewCookieMutatorFromJSON(rawConfig json.RawMessage) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}
