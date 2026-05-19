package source

import (
	"context"
	"errors"
	"slices"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrProviderDependencyNotDeclared = errors.New("provider dependency not declared")

type providerObserver struct {
	name string
	o    Observer
}

func (o *providerObserver) Notify(evt types.ChangeEvent) {
	o.o.Notify(Event{
		Source:    o.name,
		Selectors: evt.Selectors,
	})
}

type secretsResolver struct {
	name string
	deps []types.SecretRef
	r    DependencyResolver
}

func (r *secretsResolver) ResolveSecret(ctx context.Context, ref types.SecretRef) (types.Secret, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveSecret(ctx, ref)
}

func (r *secretsResolver) ResolveCredentials(ctx context.Context, ref types.SecretRef) (types.Credentials, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveCredentials(ctx, ref)
}

func (r *secretsResolver) checkReference(ref types.SecretRef) error {
	if !slices.ContainsFunc(r.deps, func(dep types.SecretRef) bool {
		return dep.Source == ref.Source && dep.Selector == ref.Selector
	}) {
		return errorchain.NewWithMessagef(
			ErrProviderDependencyNotDeclared,
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

type Source struct {
	name         string
	allowInRules bool
	sr           *secretsResolver
	p            types.Provider
}

func New(
	name string,
	conf config.SecretSourceConfig,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
	so Observer,
	dr DependencyResolver,
) (*Source, error) {
	sourceLogger := logger.With().
		Str("_secret_source", name).
		Str("_secret_provider", conf.Type).
		Logger()

	observer := &providerObserver{name: name, o: so}
	resolver := &secretsResolver{name: name, r: dr}
	source := &Source{name: name, allowInRules: conf.AllowInRules, sr: resolver}

	provider, err := registry.Create(conf.Type, types.ProviderArgs{
		Config:         conf.Config,
		Logger:         sourceLogger,
		DecoderFactory: df,
		Observer:       observer,
		Resolver:       resolver,
	})
	if err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed creating secret source '%s' of type '%s'", name, conf.Type,
		).CausedBy(err)
	}

	resolver.deps = slices.Clone(provider.Dependencies())
	source.p = provider

	return source, nil
}

func (s *Source) Name() string                    { return s.name }
func (s *Source) AccessFromRulesAllowed() bool    { return s.allowInRules }
func (s *Source) Dependencies() []types.SecretRef { return s.sr.deps }
func (s *Source) Start(ctx context.Context) error { return s.p.Start(ctx) }
func (s *Source) Stop(ctx context.Context) error  { return s.p.Stop(ctx) }
func (s *Source) DependsOn(evt Event) bool        { return s.sr.dependsOn(evt) }

func (s *Source) GetSecret(ctx context.Context, selector types.Selector) (types.Secret, error) {
	return s.p.GetSecret(ctx, selector)
}

func (s *Source) GetSecretSet(ctx context.Context, selector types.Selector) ([]types.Secret, error) {
	return s.p.GetSecretSet(ctx, selector)
}

func (s *Source) GetCredentials(ctx context.Context, selector types.Selector) (types.Credentials, error) {
	return s.p.GetCredentials(ctx, selector)
}
