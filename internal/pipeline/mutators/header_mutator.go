package mutators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type headerMutator struct{}

func NewHeaderMutatorFromJSON(rawConfig json.RawMessage) (headerMutator, error) {
	return headerMutator{}, nil
}

func (headerMutator) Mutate(context.Context, *heimdall.SubjectContext) error {
	return nil
}
