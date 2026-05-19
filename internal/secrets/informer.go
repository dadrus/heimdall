package secrets

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/dadrus/heimdall/internal/x"
)

type MissingSecretPolicy[S any, T any] interface {
	HandleMissingSecret(ctx context.Context, cch *Informer[S, T], err error) error
}

type (
	KeepPrevious[S any, T any]     struct{}
	KeepPreviousSecret[T any]      = KeepPrevious[Secret, T]
	KeepPreviousCredentials[T any] = KeepPrevious[Credentials, T]
)

func (KeepPrevious[S, T]) HandleMissingSecret(context.Context, *Informer[S, T], error) error {
	return nil
}

type (
	Clear[S any, T any]     struct{}
	ClearSecret[T any]      = Clear[Secret, T]
	ClearCredentials[T any] = Clear[Credentials, T]
)

func (Clear[S, T]) HandleMissingSecret(_ context.Context, w *Informer[S, T], _ error) error {
	w.clear()

	return nil
}

type (
	Fail[S any, T any]     struct{}
	FailSecret[T any]      = Fail[Secret, T]
	FailCredentials[T any] = Fail[Credentials, T]
)

func (Fail[S, T]) HandleMissingSecret(_ context.Context, _ *Informer[S, T], err error) error {
	return err
}

type Converter[S any, T any] func(S) (T, error)

type Source[S any] interface {
	Resolve(ctx context.Context, mgr Manager, ref Reference) (S, error)
}

type SecretSource struct{}

func (SecretSource) Resolve(ctx context.Context, sm Manager, ref Reference) (Secret, error) {
	return sm.ResolveSecret(ctx, ref)
}

type SecretSetSource struct{}

func (SecretSetSource) Resolve(
	ctx context.Context,
	sm Manager,
	ref Reference,
) ([]Secret, error) {
	return sm.ResolveSecretSet(ctx, ref)
}

type CredentialsSource struct{}

func (CredentialsSource) Resolve(
	ctx context.Context,
	sm Manager,
	ref Reference,
) (Credentials, error) {
	return sm.ResolveCredentials(ctx, ref)
}

type state[T any] struct {
	value T
	ok    bool
}

type SecretInformer[T any] struct {
	Manager             Manager
	Reference           Reference
	Converter           Converter[Secret, T]
	MissingSecretPolicy MissingSecretPolicy[Secret, T]
	OnUpdate            func(context.Context, Secret, T)
	OnError             func(context.Context, error)

	i Informer[Secret, T]
}

func (i *SecretInformer[T]) Start(ctx context.Context) error {
	i.i = Informer[Secret, T]{
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
	Manager             Manager
	Reference           Reference
	Converter           Converter[Credentials, T]
	MissingSecretPolicy MissingSecretPolicy[Credentials, T]
	OnUpdate            func(context.Context, Credentials, T)
	OnError             func(context.Context, error)

	i Informer[Credentials, T]
}

func (i *CredentialsInformer[T]) Start(ctx context.Context) error {
	i.i = Informer[Credentials, T]{
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
	Manager             Manager
	Reference           Reference
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
		return fmt.Errorf("%w: %w", ErrSubscribeFailed, err)
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

		if !strict && errors.Is(err, ErrSecretNotFound) {
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
