package mutators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeMutator []handler.Mutator

func (cm CompositeMutator) Mutate(c context.Context, sc *heimdall.SubjectContext) (err error) {
	for _, m := range cm {
		err = m.Mutate(c, sc)
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
