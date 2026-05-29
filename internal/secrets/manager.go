package secrets

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/source"
)

type Manager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error

	Resolver() Resolver
	ScopedResolverFactory() ScopedResolverFactory
}

func NewManager(
	cfg *config.Configuration,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
	meter metric.Meter,
) (Manager, error) {
	proxy := &dependencyResolverProxy{}

	repository, err := source.NewRepository(cfg, logger, df, proxy)
	if err != nil {
		return nil, err
	}

	resolver, err := newResolver(logger, repository, meter)
	if err != nil {
		return nil, err
	}

	proxy.resolver = resolver

	return &manager{
		repository: repository,
		resolver:   resolver,
		logger:     logger,
	}, nil
}

type manager struct {
	repository source.Repository
	resolver   *resolver
	logger     zerolog.Logger
}

func (r *manager) Resolver() Resolver {
	return r.resolver.globalResolver()
}

func (r *manager) ScopedResolverFactory() ScopedResolverFactory {
	return scopedResolverFactoryFunc(r.resolver.scopedResolver)
}

func (r *manager) Start(ctx context.Context) error {
	r.logger.Info().Msg("Starting secrets manager")

	if err := r.repository.Start(ctx); err != nil {
		return err
	}

	r.resolver.Start()
	r.logger.Info().Msg("Waiting for referenced secrets to become available")

	if err := r.resolver.AwaitReady(ctx); err != nil {
		_ = r.repository.Stop(ctx)
		r.resolver.Stop()

		return err
	}

	r.logger.Info().Msg("Secrets manager started")

	return nil
}

func (r *manager) Stop(ctx context.Context) error {
	r.logger.Info().Msg("Tearing down secrets manager")

	err := r.repository.Stop(ctx)

	r.resolver.Stop()

	if err == nil {
		r.logger.Info().Msg("Secrets manager stopped")
	}

	return err
}

type scopedResolverFactoryFunc func(id string, opts ...ScopeOption) ScopedResolver

func (f scopedResolverFactoryFunc) Create(id string, opts ...ScopeOption) ScopedResolver {
	return f(id, opts...)
}

type dependencyResolverProxy struct {
	resolver source.DependenciesResolver
}

func (p *dependencyResolverProxy) ResolveSecret(
	ctx context.Context,
	ref Reference,
) (Secret, error) {
	return p.resolver.ResolveSecret(ctx, ref)
}

func (p *dependencyResolverProxy) ResolveCredentials(
	ctx context.Context,
	ref Reference,
) (Credentials, error) {
	return p.resolver.ResolveCredentials(ctx, ref)
}

func (p *dependencyResolverProxy) ResolveCertificateBundle(
	ctx context.Context,
	ref Reference,
) (CertificateBundle, error) {
	return p.resolver.ResolveCertificateBundle(ctx, ref)
}
