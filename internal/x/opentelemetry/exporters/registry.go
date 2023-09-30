package exporters

import (
	"context"
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrDuplicateRegistration = errors.New("duplicate registration")

type FactoryFunc[T any] func(ctx context.Context) (T, error)

type registry[T any] struct {
	mu    sync.Mutex
	names map[string]FactoryFunc[T]
}

func (r *registry[T]) load(key string) (FactoryFunc[T], bool) {
	r.mu.Lock()
	f, ok := r.names[key]
	r.mu.Unlock()

	return f, ok
}

func (r *registry[T]) store(key string, value FactoryFunc[T]) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.names == nil {
		r.names = map[string]FactoryFunc[T]{key: value}

		return nil
	}

	if _, ok := r.names[key]; ok {
		return errorchain.NewWithMessage(ErrDuplicateRegistration, key)
	}

	r.names[key] = value

	return nil
}
