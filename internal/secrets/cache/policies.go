package cache

import (
	"context"

	"github.com/dadrus/heimdall/internal/secrets"
)

type MissingSecretPolicy[S any, T any] interface {
	HandleMissingSecret(ctx context.Context, cch *Resolver[S, T], err error) error
}

type (
	KeepPrevious[S any, T any]     struct{}
	KeepPreviousSecret[T any]      = KeepPrevious[secrets.Secret, T]
	KeepPreviousCredentials[T any] = KeepPrevious[secrets.Credentials, T]
)

func (KeepPrevious[S, T]) HandleMissingSecret(context.Context, *Resolver[S, T], error) error {
	return nil
}

type (
	Clear[S any, T any]     struct{}
	ClearSecret[T any]      = Clear[secrets.Secret, T]
	ClearCredentials[T any] = Clear[secrets.Credentials, T]
)

func (Clear[S, T]) HandleMissingSecret(_ context.Context, w *Resolver[S, T], _ error) error {
	w.clear()

	return nil
}

type (
	Fail[S any, T any]     struct{}
	FailSecret[T any]      = Fail[secrets.Secret, T]
	FailCredentials[T any] = Fail[secrets.Credentials, T]
)

func (Fail[S, T]) HandleMissingSecret(_ context.Context, _ *Resolver[S, T], err error) error {
	return err
}
