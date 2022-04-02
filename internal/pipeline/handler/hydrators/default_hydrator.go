package hydrators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type defaultHydrator struct{}

func NewDefaultHydrator(rawConfig map[string]any) (defaultHydrator, error) {
	return defaultHydrator{}, nil
}

func (defaultHydrator) Hydrate(context.Context, *heimdall.SubjectContext) error {
	return nil
}

func (defaultHydrator) WithConfig(config map[string]any) (handler.Hydrator, error) {
	return nil, nil
}
