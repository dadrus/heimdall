package mutators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerMutatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTHeader {
				return false, nil, nil
			}

			mut, err := newHeaderMutator(conf)

			return true, mut, err
		})
}

type headerMutator struct{}

func newHeaderMutator(rawConfig map[string]any) (headerMutator, error) {
	return headerMutator{}, nil
}

func (headerMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (headerMutator) WithConfig(config map[string]any) (Mutator, error) {
	return nil, nil
}
