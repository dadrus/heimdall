package mutators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeMutator []handler.Mutator

func (cm CompositeMutator) Mutate(ctx heimdall.Context, sub *subject.Subject) (err error) {
	for _, m := range cm {
		err = m.Mutate(ctx, sub)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}

	return err
}

func (cm CompositeMutator) WithConfig(_ map[string]any) (handler.Mutator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
