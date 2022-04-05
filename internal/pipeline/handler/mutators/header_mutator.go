package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type headerMutator struct{}

func NewHeaderMutator(rawConfig map[string]any) (headerMutator, error) {
	return headerMutator{}, nil
}

func (headerMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (headerMutator) WithConfig(config map[string]any) (handler.Mutator, error) {
	return nil, nil
}
