package secrets2

import (
	"context"

	"github.com/dadrus/heimdall/internal/secrets2/types"
)

type ResolveMode uint8

const (
	ResolveLazy ResolveMode = iota
	ResolveEager
)

type (
	Secret              = types.Secret
	StringSecret        = types.StringSecret
	SymmetricKeySecret  = types.SymmetricKeySecret
	AsymmetricKeySecret = types.AsymmetricKeySecret
	Credentials         = types.Credentials
	CertificateBundle   = types.CertificateBundle

	Reference = types.Reference

	resolveOptions struct {
		mode ResolveMode
	}

	ResolveOption func(*resolveOptions)

	UpdateFunc[T any] func(context.Context, T) error

	Handle[T any] interface {
		Get(ctx context.Context) (T, bool)
		OnUpdate(UpdateFunc[T])
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

	Resolver interface {
		Secret(ctx context.Context, ref Reference, opts ...ResolveOption) (SecretHandle, error)
		SecretSet(ctx context.Context, ref Reference, opts ...ResolveOption) (SecretSetHandle, error)
		Credentials(ctx context.Context, ref Reference, opts ...ResolveOption) (CredentialsHandle, error)
		CertificateBundle(ctx context.Context, ref Reference, opts ...ResolveOption) (CertificateBundleHandle, error)
	}

	RuleScopedResolver interface {
		Resolver
		Release()
	}

	ScopeOption func(*scopeOptions)

	scopeOptions struct {
		namespace string
	}

	Resolvers interface {
		Resolver() Resolver
		ScopedResolver(scopeID string, opts ...ScopeOption) RuleScopedResolver
	}
)

func WithNamespace(namespace string) ScopeOption {
	return func(opts *scopeOptions) {
		opts.namespace = namespace
	}
}

func Lazy() ResolveOption {
	return func(opts *resolveOptions) {
		opts.mode = ResolveLazy
	}
}

func Eager() ResolveOption {
	return func(opts *resolveOptions) {
		opts.mode = ResolveEager
	}
}
