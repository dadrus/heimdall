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
			if typ != config.POTJwt {
				return false, nil, nil
			}

			mut, err := newJWTMutator(conf)

			return true, mut, err
		})
}

type jwtMutator struct{}

func newJWTMutator(rawConfig map[string]any) (jwtMutator, error) {
	return jwtMutator{}, nil
}

func (jwtMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (jwtMutator) WithConfig(config map[string]any) (Mutator, error) {
	return nil, nil
}
