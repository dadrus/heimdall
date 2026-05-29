package secrets

import (
	"context"

	"github.com/dadrus/heimdall/internal/secrets/types"
)

type (
	Secret              = types.Secret
	StringSecret        = types.StringSecret
	SymmetricKeySecret  = types.SymmetricKeySecret
	AsymmetricKeySecret = types.AsymmetricKeySecret
	Credentials         = types.Credentials
	CertificateBundle   = types.CertificateBundle

	Reference = types.Reference

	UpdateFunc[T any] func(context.Context, T) error

	Handle[T any] interface {
		Get() (T, bool)
		OnUpdate(callback UpdateFunc[T])
	}

	SecretHandle interface {
		Handle[Secret]
	}

	SecretSetHandle interface {
		Handle[[]Secret]
	}

	CredentialsHandle interface {
		Handle[Credentials]
	}

	CertificateBundleHandle interface {
		Handle[CertificateBundle]
	}

	ReadyAwaiter interface {
		AwaitReady(ctx context.Context) error
	}

	Resolver interface {
		Secret(ref Reference) (SecretHandle, error)
		SecretSet(ref Reference) (SecretSetHandle, error)
		Credentials(ref Reference) (CredentialsHandle, error)
		CertificateBundle(ref Reference) (CertificateBundleHandle, error)
	}

	ScopedResolver interface {
		Resolver
		ReadyAwaiter
		Release()
	}

	ScopeOption func(*scopeOptions)

	scopeOptions struct {
		namespace  string
		isInternal bool
	}

	ScopedResolverFactory interface {
		Create(id string, opts ...ScopeOption) ScopedResolver
	}
)

func WithNamespace(namespace string) ScopeOption {
	return func(opts *scopeOptions) {
		opts.namespace = namespace
	}
}

func WithInternalScope() ScopeOption {
	return func(opts *scopeOptions) {
		opts.isInternal = true
	}
}
