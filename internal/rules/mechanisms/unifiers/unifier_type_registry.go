package unifiers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedUnifierType = errors.New("unifier type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	typeFactories []UnifierTypeFactory
	// nolint
	typeFactoriesMu sync.RWMutex
)

type UnifierTypeFactory func(id string, typ string, c map[string]any) (bool, Unifier, error)

func registerUnifierTypeFactory(factory UnifierTypeFactory) {
	typeFactoriesMu.Lock()
	defer typeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterUnifierType factory is nil")
	}

	typeFactories = append(typeFactories, factory)
}

func CreateUnifierPrototype(id string, typ string, mConfig map[string]any) (Unifier, error) {
	typeFactoriesMu.RLock()
	defer typeFactoriesMu.RUnlock()

	for _, create := range typeFactories {
		if ok, at, err := create(id, typ, mConfig); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedUnifierType, "'%s'", typ)
}
