package authorizers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedAuthorizerType = errors.New("authorizer type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	authorizerTypeFactories []AuthorizerTypeFactory
	// nolint
	authorizerTypeFactoriesMu sync.RWMutex
)

type AuthorizerTypeFactory func(id string, typ string, config map[string]any) (bool, Authorizer, error)

func registerAuthorizerTypeFactory(factory AuthorizerTypeFactory) {
	authorizerTypeFactoriesMu.Lock()
	defer authorizerTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterAuthorizerType factory is nil")
	}

	authorizerTypeFactories = append(authorizerTypeFactories, factory)
}

func CreateAuthorizerPrototype(id string, typ string, config map[string]any) (Authorizer, error) {
	authorizerTypeFactoriesMu.RLock()
	defer authorizerTypeFactoriesMu.RUnlock()

	for _, create := range authorizerTypeFactories {
		if ok, at, err := create(id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedAuthorizerType, "'%s'", typ)
}
