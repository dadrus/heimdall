package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeMutator []Mutator

func (cm CompositeMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) error {
	for _, m := range cm {
		err := m.Mutate(ctx, sub)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cm CompositeMutator) WithConfig(_ map[string]any) (Mutator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
