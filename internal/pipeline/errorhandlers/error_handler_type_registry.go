package errorhandlers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedErrorHandlerType = errors.New("error handler type unsupported")

	errorHandlerTypeFactories   []ErrorHandlerTypeFactory
	errorHandlerTypeFactoriesMu sync.RWMutex
)

type ErrorHandlerTypeFactory func(t config.PipelineObjectType, c map[any]any) (bool, ErrorHandler, error)

func registerErrorHandlerTypeFactory(factory ErrorHandlerTypeFactory) {
	errorHandlerTypeFactoriesMu.Lock()
	defer errorHandlerTypeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterErrorHandler factory is nil")
	}

	errorHandlerTypeFactories = append(errorHandlerTypeFactories, factory)
}

func CreateErrorHandlerPrototype(typ config.PipelineObjectType, config map[any]any) (ErrorHandler, error) {
	errorHandlerTypeFactoriesMu.RLock()
	defer errorHandlerTypeFactoriesMu.RUnlock()

	for _, create := range errorHandlerTypeFactories {
		if ok, at, err := create(typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedErrorHandlerType, "'%s'", typ)
}
