package authenticators

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedAuthenticatorType = errors.New("authenticator type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	authenticatorTypeFactories []AuthenticatorTypeFactory
	// nolint
	authenticatorTypeFactoriesMu sync.RWMutex
)

type AuthenticatorTypeFactory func(typ config.PipelineObjectType, config map[string]any) (bool, Authenticator, error)

func RegisterAuthenticatorTypeFactory(factory AuthenticatorTypeFactory) {
	authenticatorTypeFactoriesMu.Lock()
	defer authenticatorTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterAuthenticatorType factory is nil")
	}

	authenticatorTypeFactories = append(authenticatorTypeFactories, factory)
}

func CreateAuthenticatorPrototype(typ config.PipelineObjectType, config map[string]any) (Authenticator, error) {
	authenticatorTypeFactoriesMu.RLock()
	defer authenticatorTypeFactoriesMu.RUnlock()

	for _, create := range authenticatorTypeFactories {
		if ok, at, err := create(typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedAuthenticatorType, "'%s'", typ)
}
