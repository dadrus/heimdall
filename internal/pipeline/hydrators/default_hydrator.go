package hydrators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type defaultHydrator struct{}

func NewDefaultHydratorFromJSON(rawConfig json.RawMessage) (defaultHydrator, error) {
	return defaultHydrator{}, nil
}

func (defaultHydrator) Hydrate(context.Context, *heimdall.SubjectContext) error {
	return nil
}
