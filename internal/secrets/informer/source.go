package informer

import (
	"context"

	"github.com/dadrus/heimdall/internal/secrets"
)

type Source[S any] interface {
	Resolve(ctx context.Context, mgr secrets.Manager, ref secrets.Reference) (S, error)
}

type SecretSource struct{}

func (SecretSource) Resolve(ctx context.Context, sm secrets.Manager, ref secrets.Reference) (secrets.Secret, error) {
	return sm.ResolveSecret(ctx, ref)
}

type SecretSetSource struct{}

func (SecretSetSource) Resolve(
	ctx context.Context,
	sm secrets.Manager,
	ref secrets.Reference,
) ([]secrets.Secret, error) {
	return sm.ResolveSecretSet(ctx, ref)
}

type CredentialsSource struct{}

func (CredentialsSource) Resolve(
	ctx context.Context,
	sm secrets.Manager,
	ref secrets.Reference,
) (secrets.Credentials, error) {
	return sm.ResolveCredentials(ctx, ref)
}
