package mutators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	RegisterMutatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Mutator, error) {
			if typ != config.POTCookie {
				return false, nil, nil
			}

			mut, err := newCookieMutator(conf)

			return true, mut, err
		})
}

type cookieMutator struct{}

func newCookieMutator(rawConfig map[string]any) (cookieMutator, error) {
	return cookieMutator{}, nil
}

func (cookieMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (cookieMutator) WithConfig(config map[string]any) (Mutator, error) {
	return nil, nil
}
