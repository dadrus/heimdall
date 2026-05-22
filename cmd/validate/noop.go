package validate

import (
	"context"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/keyregistry"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/secrets"
)

type noopRepository struct{}

func (noopRepository) FindRule(_ pipeline.Context) (rule.Rule, error) {
	return nil, errFunctionNotSupported
}
func (noopRepository) AddRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) error { return nil }
func (noopRepository) UpdateRuleSet(_ context.Context, _ rule.RuleSet, _ []rule.Rule) ([]rule.Rule, error) {
	return nil, errFunctionNotSupported
}

func (noopRepository) DeleteRuleSet(_ context.Context, _ rule.RuleSet) ([]rule.Rule, error) {
	return nil, errFunctionNotSupported
}

type noopRegistry struct{}

func (noopRegistry) Notify(_ keyregistry.KeyInfo) {}
func (noopRegistry) Keys() []jose.JSONWebKey      { return nil }

type noopResolver struct{}

func (noopResolver) Secret(
	context.Context,
	secrets.Reference,
	...secrets.ResolveOption,
) (secrets.SecretHandle, error) {
	return noopHandle[secrets.Secret]{}, nil
}

func (noopResolver) SecretSet(
	context.Context,
	secrets.Reference,
	...secrets.ResolveOption,
) (secrets.SecretSetHandle, error) {
	return noopHandle[[]secrets.Secret]{}, nil
}

func (noopResolver) Credentials(
	context.Context,
	secrets.Reference,
	...secrets.ResolveOption,
) (secrets.CredentialsHandle, error) {
	return noopHandle[secrets.Credentials]{}, nil
}

func (noopResolver) CertificateBundle(
	context.Context,
	secrets.Reference,
	...secrets.ResolveOption,
) (secrets.CertificateBundleHandle, error) {
	return noopHandle[secrets.CertificateBundle]{}, nil
}

type noopHandle[T any] struct{}

func (noopHandle[T]) Get(context.Context) (T, bool) {
	var zero T

	return zero, false
}

func (noopHandle[T]) OnUpdate(secrets.UpdateFunc[T]) {}
