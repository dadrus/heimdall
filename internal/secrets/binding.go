package secrets

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

type bindingKey struct {
	source    string
	selector  string
	namespace string
}

type bindingState uint8

const (
	bindingIdle bindingState = iota
	bindingScheduled
	bindingRunning
	bindingClosed
)

type binding struct {
	bindingKey

	logger           zerolog.Logger
	nextSubscriberID uint64

	callbacksMu sync.RWMutex
	callbacks   map[uint64]func(context.Context) error

	stateMu      sync.Mutex
	state        bindingState
	eventPending bool

	wg sync.WaitGroup
}

func newBinding(bk bindingKey, logger zerolog.Logger) *binding {
	return &binding{
		bindingKey: bk,
		logger:     logger,
		callbacks:  make(map[uint64]func(context.Context) error),
	}
}

func (b *binding) addSubscriber(cb func(context.Context) error) uint64 {
	b.callbacksMu.Lock()
	defer b.callbacksMu.Unlock()

	b.nextSubscriberID++
	id := b.nextSubscriberID
	b.callbacks[id] = cb

	return id
}

// removeSubscriber removes a callback and reports whether the binding still has callbacks.
func (b *binding) removeSubscriber(id uint64) bool {
	b.callbacksMu.Lock()
	defer b.callbacksMu.Unlock()

	delete(b.callbacks, id)

	return len(b.callbacks) > 0
}

func (b *binding) schedule() bool {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()

	if b.state == bindingClosed {
		return false
	}

	b.eventPending = true

	switch b.state {
	case bindingIdle:
		b.state = bindingScheduled

		return true
	case bindingScheduled, bindingRunning:
		return false
	default:
		return false
	}
}

func (b *binding) unschedule() {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()

	if b.state == bindingScheduled {
		b.state = bindingIdle
		b.eventPending = false
	}
}

func (b *binding) beginRun() bool {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()

	if b.state != bindingScheduled {
		return false
	}

	b.state = bindingRunning
	b.eventPending = false
	b.wg.Add(1)

	return true
}

func (b *binding) finishRun() bool {
	defer b.wg.Done()

	b.stateMu.Lock()
	defer b.stateMu.Unlock()

	if b.state == bindingClosed {
		return false
	}

	if b.eventPending {
		b.state = bindingScheduled

		return true
	}

	b.state = bindingIdle

	return false
}

func (b *binding) runCallbacks() {
	b.callbacksMu.RLock()

	callbacks := make([]func(context.Context) error, 0, len(b.callbacks))
	for _, cb := range b.callbacks {
		callbacks = append(callbacks, cb)
	}

	b.callbacksMu.RUnlock()

	for _, cb := range callbacks {
		if err := cb(context.Background()); err != nil {
			b.logger.Warn().
				Err(err).
				Str("_source", b.source).
				Str("_namespace", b.namespace).
				Str("_selector", b.selector).
				Msg("Secret update callback failed")
		}
	}
}

func (b *binding) stop() {
	b.stateMu.Lock()
	b.state = bindingClosed
	b.eventPending = false
	b.stateMu.Unlock()

	b.wg.Wait()
}
