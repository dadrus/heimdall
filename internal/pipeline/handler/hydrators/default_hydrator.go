package hydrators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type defaultHydrator struct{}

func NewDefaultHydratorFromJSON(rawConfig json.RawMessage) (defaultHydrator, error) {
	return defaultHydrator{}, nil
}

func (defaultHydrator) Hydrate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (defaultHydrator) WithConfig(config []byte) (handler.Hydrator, error) {
	return nil, nil
}
