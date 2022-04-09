package hydrators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeHydrator []Hydrator

func (ch CompositeHydrator) Hydrate(ctx heimdall.Context, sub *subject.Subject) (err error) {
	for _, h := range ch {
		err = h.Hydrate(ctx, sub)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ch CompositeHydrator) WithConfig(_ map[string]any) (Hydrator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
