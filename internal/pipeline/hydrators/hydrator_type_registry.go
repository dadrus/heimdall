package hydrators

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedHydratorType = errors.New("hydrator type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	hydratorTypeFactories []HydratorTypeFactory
	// nolint
	hydratorTypeFactoriesMu sync.RWMutex
)

type HydratorTypeFactory func(id string, t config.PipelineHandlerType, c map[string]any) (bool, Hydrator, error)

func registerHydratorTypeFactory(factory HydratorTypeFactory) {
	hydratorTypeFactoriesMu.Lock()
	defer hydratorTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterHydratorType factory is nil")
	}

	hydratorTypeFactories = append(hydratorTypeFactories, factory)
}

func CreateHydratorPrototype(id string, typ config.PipelineHandlerType, config map[string]any) (Hydrator, error) {
	hydratorTypeFactoriesMu.RLock()
	defer hydratorTypeFactoriesMu.RUnlock()

	for _, create := range hydratorTypeFactories {
		if ok, at, err := create(id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedHydratorType, "'%s'", typ)
}
