package source

import (
	"context"
	"slices"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type secretsResolver struct {
	name string
	deps []types.Reference
	r    provider.DependenciesResolver
}

func (r *secretsResolver) ResolveSecret(
	ctx context.Context,
	ref types.Reference,
) (types.Secret, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveSecret(ctx, ref)
}

func (r *secretsResolver) ResolveCredentials(
	ctx context.Context,
	ref types.Reference,
) (types.Credentials, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveCredentials(ctx, ref)
}

func (r *secretsResolver) ResolveCertificateBundle(
	ctx context.Context,
	ref types.Reference,
) (types.CertificateBundle, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveCertificateBundle(ctx, ref)
}

func (r *secretsResolver) checkReference(ref types.Reference) error {
	if !slices.ContainsFunc(r.deps, func(dep types.Reference) bool {
		return dep.Source == ref.Source && dep.Selector == ref.Selector
	}) {
		return errorchain.NewWithMessagef(
			types.ErrDependencyNotDeclared,
			"secret reference '%s/%s' is not a declared dependency of secret source '%s'",
			ref.Source,
			ref.Selector,
			r.name,
		)
	}

	return nil
}

func (r *secretsResolver) dependsOn(evt Event) bool {
	for _, dep := range r.deps {
		if dep.Source != evt.Source {
			continue
		}

		if len(evt.Selectors) == 0 {
			return true
		}

		for _, selector := range evt.Selectors {
			if dep.Selector == selector.Value {
				return true
			}
		}
	}

	return false
}
