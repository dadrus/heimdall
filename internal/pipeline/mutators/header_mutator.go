package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type headerMutator struct{}

func NewHeaderMutatorFromJSON(rawConfig json.RawMessage) (headerMutator, error) {
	return headerMutator{}, nil
}

func (headerMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (headerMutator) WithConfig(config json.RawMessage) (interfaces.Mutator, error) {
	return nil, nil
}
