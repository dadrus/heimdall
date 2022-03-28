package hydrators

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type CompositeHydrator []handler.Hydrator

func (ch CompositeHydrator) Hydrate(c context.Context, sc *heimdall.SubjectContext) error {
	var err error
	for _, h := range ch {
		err = h.Hydrate(c, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (ch CompositeHydrator) WithConfig(_ json.RawMessage) (handler.Hydrator, error) {
	return nil, errors.New("reconfiguration not allowed")
}
