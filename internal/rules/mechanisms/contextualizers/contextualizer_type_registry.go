package contextualizers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedContextualizerType = errors.New("contextualizer type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	typeFactories []ContextualizerTypeFactory
	// nolint
	typeFactoriesMu sync.RWMutex
)

type ContextualizerTypeFactory func(id string, typ string, c map[string]any) (bool, Contextualizer, error)

func registerContextualizerTypeFactory(factory ContextualizerTypeFactory) {
	typeFactoriesMu.Lock()
	defer typeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterHydratorType factory is nil")
	}

	typeFactories = append(typeFactories, factory)
}

func CreateContextualizerPrototype(id string, typ string, config map[string]any) (Contextualizer, error) {
	typeFactoriesMu.RLock()
	defer typeFactoriesMu.RUnlock()

	for _, create := range typeFactories {
		if ok, at, err := create(id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedContextualizerType, "'%s'", typ)
}
