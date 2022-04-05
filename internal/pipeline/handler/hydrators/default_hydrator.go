package hydrators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type defaultHydrator struct{}

func NewDefaultHydrator(rawConfig map[string]any) (defaultHydrator, error) {
	return defaultHydrator{}, nil
}

func (defaultHydrator) Hydrate(ctx heimdall.Context, sub *subject.Subject) error {
	return nil
}

func (defaultHydrator) WithConfig(config map[string]any) (handler.Hydrator, error) {
	return nil, nil
}
