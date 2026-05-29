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

package source

import (
	"context"
	"slices"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/task"
)

type providerObserver struct {
	name string
	o    Observer
}

func (o *providerObserver) Notify(evt provider.ChangeEvent) {
	o.o.Notify(Event{
		Source:    o.name,
		Selectors: evt.Selectors,
	})
}

type Source interface {
	Name() string
	AccessFromRulesAllowed() bool
	IsNamespaceAware() bool

	GetSecret(ctx context.Context, selector Selector) (types.Secret, error)
	GetSecretSet(ctx context.Context, selector Selector) ([]types.Secret, error)
	GetCredentials(ctx context.Context, selector Selector) (types.Credentials, error)
	GetCertificateBundle(ctx context.Context, selector Selector) (types.CertificateBundle, error)
}

type DependenciesResolver = provider.DependenciesResolver

type secretSource struct {
	task.StateMachine

	name         string
	allowInRules bool
	sr           *secretsResolver
	p            provider.Provider
	logger       zerolog.Logger
	observer     Observer
}

func newSecretSource(
	name string,
	conf config.SecretSourceConfig,
	logger zerolog.Logger,
	df encoding.DecoderFactory,
	so Observer,
	dr DependenciesResolver,
) (*secretSource, error) {
	sourceLogger := logger.With().
		Str("_secret_source", name).
		Str("_secret_provider", conf.Type).
		Logger()

	sourceLogger.Info().Msg("Creating secret source")

	observer := &providerObserver{name: name, o: so}
	resolver := &secretsResolver{name: name, r: dr}
	src := &secretSource{
		name:         name,
		allowInRules: conf.AllowInRules,
		sr:           resolver,
		logger:       sourceLogger,
		observer:     so,
	}

	prv, err := registry.Create(conf.Type, provider.Args{
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

	resolver.deps = slices.Clone(prv.Dependencies())
	src.p = prv

	return src, nil
}

func (s *secretSource) Name() string                    { return s.name }
func (s *secretSource) AccessFromRulesAllowed() bool    { return s.allowInRules }
func (s *secretSource) Dependencies() []types.Reference { return slices.Clone(s.sr.deps) }
func (s *secretSource) IsNamespaceAware() bool          { return s.p.IsNamespaceAware() }
func (s *secretSource) DependsOn(evt Event) bool        { return s.sr.dependsOn(evt) }

func (s *secretSource) Start(ctx context.Context) error {
	s.logger.Info().Msg("Starting secret source")

	return s.p.Start(ctx)
}

func (s *secretSource) Stop(ctx context.Context) error {
	s.logger.Info().Msg("Tearing down secret source")

	return s.p.Stop(ctx)
}

func (s *secretSource) GetSecret(ctx context.Context, selector Selector) (types.Secret, error) {
	s.logger.Debug().Str("_selector", selector.Value).Msg("Loading secret")

	return s.p.GetSecret(ctx, selector)
}

func (s *secretSource) GetSecretSet(ctx context.Context, selector Selector) ([]types.Secret, error) {
	s.logger.Debug().Str("_selector", selector.Value).Msg("Loading secret set")

	return s.p.GetSecretSet(ctx, selector)
}

func (s *secretSource) GetCredentials(ctx context.Context, selector Selector) (types.Credentials, error) {
	s.logger.Debug().Str("_selector", selector.Value).Msg("Loading credentials")

	return s.p.GetCredentials(ctx, selector)
}

func (s *secretSource) GetCertificateBundle(ctx context.Context, selector Selector) (types.CertificateBundle, error) {
	s.logger.Debug().Str("_selector", selector.Value).Msg("Loading certificate bundle")

	return s.p.GetCertificateBundle(ctx, selector)
}

func (s *secretSource) Unschedule(reason error) {
	s.CancelSchedule()

	if reason != nil {
		s.logger.Warn().
			Err(reason).
			Msg("Failed scheduling secret source restart task")
	}
}

func (s *secretSource) Run() {
	ctx := context.Background()

	s.logger.Debug().Msg("Restarting secret source after dependency change")

	if err := s.p.Stop(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Tearing down secret source failed")

		return
	}

	if err := s.p.Start(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Starting secret source failed")

		return
	}

	s.logger.Debug().Msg("Secret source restarted after dependency change")

	s.observer.Notify(Event{Source: s.Name()})
}

func (s *secretSource) stopTask() { s.StateMachine.Stop() }

var (
	_ task.Task = (*secretSource)(nil)
	_ Source    = (*secretSource)(nil)
)
