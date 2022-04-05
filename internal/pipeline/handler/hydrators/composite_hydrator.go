package hydrators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeHydrator []handler.Hydrator

func (ch CompositeHydrator) Hydrate(ctx heimdall.Context, sub *subject.Subject) (err error) {
	for _, h := range ch {
		err = h.Hydrate(ctx, sub)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}

	return err
}

func (ch CompositeHydrator) WithConfig(_ map[string]any) (handler.Hydrator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
