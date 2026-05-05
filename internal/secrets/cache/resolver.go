package cache

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

type SecretResolver[T any] struct {
	Manager             secrets.Manager
	Reference           secrets.Reference
	Converter           Converter[secrets.Secret, T]
	MissingSecretPolicy MissingSecretPolicy[secrets.Secret, T]
	OnUpdate            func(context.Context, secrets.Secret, T)
	OnError             func(context.Context, error)

	r Resolver[secrets.Secret, T]
}

func (r *SecretResolver[T]) Start(ctx context.Context) error {
	r.r = Resolver[secrets.Secret, T]{
		Manager:             r.Manager,
		Reference:           r.Reference,
		Source:              SecretSource{},
		Converter:           r.Converter,
		MissingSecretPolicy: r.MissingSecretPolicy,
		OnUpdate:            r.OnUpdate,
		OnError:             r.OnError,
	}

	return r.r.Start(ctx)
}

func (r *SecretResolver[T]) Stop()          { r.r.Stop() }
func (r *SecretResolver[T]) Get() (T, bool) { return r.r.Get() }

type CredentialsResolver[T any] struct {
	Manager             secrets.Manager
	Reference           secrets.Reference
	Converter           Converter[secrets.Credentials, T]
	MissingSecretPolicy MissingSecretPolicy[secrets.Credentials, T]
	OnUpdate            func(context.Context, secrets.Credentials, T)
	OnError             func(context.Context, error)

	r Resolver[secrets.Credentials, T]
}

func (r *CredentialsResolver[T]) Start(ctx context.Context) error {
	r.r = Resolver[secrets.Credentials, T]{
		Manager:             r.Manager,
		Reference:           r.Reference,
		Source:              CredentialsSource{},
		Converter:           r.Converter,
		MissingSecretPolicy: r.MissingSecretPolicy,
		OnUpdate:            r.OnUpdate,
		OnError:             r.OnError,
	}

	return r.r.Start(ctx)
}

func (r *CredentialsResolver[T]) Stop()          { r.r.Stop() }
func (r *CredentialsResolver[T]) Get() (T, bool) { return r.r.Get() }

type Resolver[S any, T any] struct {
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

func (r *Resolver[S, T]) Start(ctx context.Context) error {
	if r.Manager == nil {
		panic("secret cache: manager is nil")
	}

	if r.Source == nil {
		panic("secret cache: resolver is nil")
	}

	if r.Converter == nil {
		panic("secret cache: converter is nil")
	}

	if r.MissingSecretPolicy == nil {
		r.MissingSecretPolicy = KeepPrevious[S, T]{}
	}

	if err := r.reload(ctx, true); err != nil {
		return err
	}

	unsubscribe, err := r.Manager.Subscribe(r.Reference, func(ctx context.Context) error {
		return r.reload(ctx, false)
	})
	if err != nil {
		return fmt.Errorf("%w: %w", secrets.ErrSubscribeFailed, err)
	}

	r.unsubscribe = unsubscribe

	return nil
}

func (r *Resolver[S, T]) Stop() {
	if r.unsubscribe != nil {
		r.unsubscribe()
		r.unsubscribe = nil
	}
}

func (r *Resolver[S, T]) Get() (T, bool) {
	st := r.state.Load()
	if st == nil || !st.ok {
		var zero T

		return zero, false
	}

	return st.value, true
}

func (r *Resolver[S, T]) reload(ctx context.Context, strict bool) error {
	raw, err := r.Source.Resolve(ctx, r.Manager, r.Reference)
	if err != nil {
		if !strict && r.OnError != nil {
			r.OnError(ctx, err)
		}

		if errors.Is(err, secrets.ErrSecretNotFound) {
			return r.MissingSecretPolicy.HandleMissingSecret(ctx, r, err)
		}

		return x.IfThenElse(strict, err, nil)
	}

	value, err := r.Converter(raw)
	if err != nil {
		if !strict && r.OnError != nil {
			r.OnError(ctx, err)
		}

		return x.IfThenElse(strict, err, nil)
	}

	r.set(value)

	if r.OnUpdate != nil {
		r.OnUpdate(ctx, raw, value)
	}

	return nil
}

func (r *Resolver[S, T]) set(value T) {
	r.state.Store(&state[T]{
		value: value,
		ok:    true,
	})
}

func (r *Resolver[S, T]) clear() {
	var zero T

	r.state.Store(&state[T]{
		value: zero,
		ok:    false,
	})
}
