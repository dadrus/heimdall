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
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/secrets/source"
)

var Module = fx.Options( //nolint:gochecknoglobals
	fx.Provide(
		newDependencyResolverProxy,
		func(proxy *dependencyResolverProxy) source.DependenciesResolver { return proxy },
		newRepository,
		newResolver,
		fx.Annotate(
			newRuntime,
			fx.OnStart(func(ctx context.Context, rt *runtime) error { return rt.Start(ctx) }),
			fx.OnStop(func(ctx context.Context, rt *runtime) error { return rt.Stop(ctx) }),
		),
		func(rt *runtime) Resolver {
			return rt.resolver.globalResolver()
		},
		func(rt *runtime) ScopedResolverFactory {
			return scopedResolverFactoryFunc(rt.resolver.scopedResolver)
		},
	),
)

type scopedResolverFactoryFunc func(id string, opts ...ScopeOption) ScopedResolver

func (f scopedResolverFactoryFunc) Create(id string, opts ...ScopeOption) ScopedResolver {
	return f(id, opts...)
}

type dependencyResolverProxy struct {
	resolver source.DependenciesResolver
}

func newDependencyResolverProxy() *dependencyResolverProxy {
	return &dependencyResolverProxy{}
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

func newRepository(
	cfg *config.Configuration,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
	resolver source.DependenciesResolver,
) (source.Repository, error) {
	return source.NewRepository(cfg, logger, df, resolver)
}

func newRuntime(
	repository source.Repository,
	resolver *resolver,
	proxy *dependencyResolverProxy,
) *runtime {
	proxy.resolver = resolver

	return &runtime{
		repository: repository,
		resolver:   resolver,
	}
}

type runtime struct {
	repository source.Repository
	resolver   *resolver
}

func (r *runtime) Start(ctx context.Context) error {
	return r.repository.Start(ctx)
}

func (r *runtime) Stop(ctx context.Context) error {
	r.resolver.Stop()

	return r.repository.Stop(ctx)
}
