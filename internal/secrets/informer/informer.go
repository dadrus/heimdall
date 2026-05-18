package informer

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
)

type Converter[S any, T any] func(S) (T, error)

type state[T any] struct {
	value T
	ok    bool
}

type SecretInformer[T any] struct {
	Manager             secrets.Manager
	Reference           secrets.Reference
	Converter           Converter[secrets.Secret, T]
	MissingSecretPolicy MissingSecretPolicy[secrets.Secret, T]
	OnUpdate            func(context.Context, secrets.Secret, T)
	OnError             func(context.Context, error)

	i Informer[secrets.Secret, T]
}

func (i *SecretInformer[T]) Start(ctx context.Context) error {
	i.i = Informer[secrets.Secret, T]{
		Manager:             i.Manager,
		Reference:           i.Reference,
		Source:              SecretSource{},
		Converter:           i.Converter,
		MissingSecretPolicy: i.MissingSecretPolicy,
		OnUpdate:            i.OnUpdate,
		OnError:             i.OnError,
	}

	return i.i.Start(ctx)
}

func (i *SecretInformer[T]) Stop()          { i.i.Stop() }
func (i *SecretInformer[T]) Get() (T, bool) { return i.i.Get() }

type CredentialsInformer[T any] struct {
	Manager             secrets.Manager
	Reference           secrets.Reference
	Converter           Converter[secrets.Credentials, T]
	MissingSecretPolicy MissingSecretPolicy[secrets.Credentials, T]
	OnUpdate            func(context.Context, secrets.Credentials, T)
	OnError             func(context.Context, error)

	i Informer[secrets.Credentials, T]
}

func (i *CredentialsInformer[T]) Start(ctx context.Context) error {
	i.i = Informer[secrets.Credentials, T]{
		Manager:             i.Manager,
		Reference:           i.Reference,
		Source:              CredentialsSource{},
		Converter:           i.Converter,
		MissingSecretPolicy: i.MissingSecretPolicy,
		OnUpdate:            i.OnUpdate,
		OnError:             i.OnError,
	}

	return i.i.Start(ctx)
}

func (i *CredentialsInformer[T]) Stop()          { i.i.Stop() }
func (i *CredentialsInformer[T]) Get() (T, bool) { return i.i.Get() }

type Informer[S any, T any] struct {
	Manager             secrets.Manager
	Reference           secrets.Reference
	Source              Source[S]
	Converter           Converter[S, T]
	MissingSecretPolicy MissingSecretPolicy[S, T]
	OnUpdate            func(context.Context, S, T)
	OnError             func(context.Context, error)

	state       atomic.Pointer[state[T]]
	unsubscribe func()
}

func (i *Informer[S, T]) Start(ctx context.Context) error {
	if i.Manager == nil {
		panic("secret cache: manager is nil")
	}

	if i.Source == nil {
		panic("secret cache: resolver is nil")
	}

	if i.Converter == nil {
		panic("secret cache: converter is nil")
	}

	if i.MissingSecretPolicy == nil {
		i.MissingSecretPolicy = KeepPrevious[S, T]{}
	}

	if err := i.reload(ctx, true); err != nil {
		return err
	}

	unsubscribe, err := i.Manager.Subscribe(i.Reference, func(ctx context.Context) error {
		return i.reload(ctx, false)
	})
	if err != nil {
		return fmt.Errorf("%w: %w", secrets.ErrSubscribeFailed, err)
	}

	i.unsubscribe = unsubscribe

	return nil
}

func (i *Informer[S, T]) Stop() {
	if i.unsubscribe != nil {
		i.unsubscribe()
		i.unsubscribe = nil
	}
}

func (i *Informer[S, T]) Get() (T, bool) {
	st := i.state.Load()
	if st == nil || !st.ok {
		var zero T

		return zero, false
	}

	return st.value, true
}

func (i *Informer[S, T]) reload(ctx context.Context, strict bool) error {
	raw, err := i.Source.Resolve(ctx, i.Manager, i.Reference)
	if err != nil {
		if !strict && i.OnError != nil {
			i.OnError(ctx, err)
		}

		if !strict && errors.Is(err, secrets.ErrSecretNotFound) {
			return i.MissingSecretPolicy.HandleMissingSecret(ctx, i, err)
		}

		return x.IfThenElse(strict, err, nil)
	}

	value, err := i.Converter(raw)
	if err != nil {
		if !strict && i.OnError != nil {
			i.OnError(ctx, err)
		}

		return x.IfThenElse(strict, err, nil)
	}

	i.set(value)

	if i.OnUpdate != nil {
		i.OnUpdate(ctx, raw, value)
	}

	return nil
}

func (i *Informer[S, T]) set(value T) {
	i.state.Store(&state[T]{
		value: value,
		ok:    true,
	})
}

func (i *Informer[S, T]) clear() {
	var zero T

	i.state.Store(&state[T]{
		value: zero,
		ok:    false,
	})
}
