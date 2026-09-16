// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

	logger.Info().Msg("Initializing secrets manager")

	repository, err := source.NewRepository(cfg, logger, df, proxy)
	if err != nil {
		return nil, err
	}

	resolver, err := newResolver(logger, repository, meter)
	if err != nil {
		return nil, err
	}

	logger.Info().Msg("Secrets manager initialized")

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

type scopedResolverFactoryFunc func(opts ...ScopeOption) ScopedResolver

func (f scopedResolverFactoryFunc) Create(opts ...ScopeOption) ScopedResolver {
	return f(opts...)
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
