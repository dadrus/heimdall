package mutators

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedMutatorType = errors.New("mutator type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	mutatorTypeFactories []MutatorTypeFactory
	// nolint
	mutatorTypeFactoriesMu sync.RWMutex
)

type MutatorTypeFactory func(id string, typ string, c map[string]any) (bool, Mutator, error)

func registerMutatorTypeFactory(factory MutatorTypeFactory) {
	mutatorTypeFactoriesMu.Lock()
	defer mutatorTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterMutatorType factory is nil")
	}

	mutatorTypeFactories = append(mutatorTypeFactories, factory)
}

func CreateMutatorPrototype(id string, typ string, mConfig map[string]any) (Mutator, error) {
	mutatorTypeFactoriesMu.RLock()
	defer mutatorTypeFactoriesMu.RUnlock()

	for _, create := range mutatorTypeFactories {
		if ok, at, err := create(id, typ, mConfig); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedMutatorType, "'%s'", typ)
}
