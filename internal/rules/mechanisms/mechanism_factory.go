// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package mechanisms

import (
	"errors"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrAuthenticatorCreation  = errors.New("failed to create authenticator")
	ErrAuthorizerCreation     = errors.New("failed to create authorizer")
	ErrFinalizerCreation      = errors.New("failed to create finalizer")
	ErrContextualizerCreation = errors.New("failed to create contextualizer")
	ErrErrorHandlerCreation   = errors.New("failed to create error handler")
)

//go:generate mockery --name MechanismFactory --structname MechanismFactoryMock

type MechanismFactory interface {
	CreateAuthenticator(version, id string, conf config.MechanismConfig) (authenticators.Authenticator, error)
	CreateAuthorizer(version, id string, conf config.MechanismConfig) (authorizers.Authorizer, error)
	CreateContextualizer(version, id string, conf config.MechanismConfig) (contextualizers.Contextualizer, error)
	CreateFinalizer(version, id string, conf config.MechanismConfig) (finalizers.Finalizer, error)
	CreateErrorHandler(version, id string, conf config.MechanismConfig) (errorhandlers.ErrorHandler, error)
}

func NewMechanismFactory(
	conf *config.Configuration,
	logger zerolog.Logger,
	fw watcher.Watcher,
	khr keyholder.Registry,
	co certificate.Observer,
) (MechanismFactory, error) {
	logger.Info().Msg("Loading mechanism catalogue")

	repository, err := newMechanismRepository(conf, logger, fw, khr, co)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading mechanism catalogue")

		return nil, err
	}

	return &mechanismsFactory{r: repository}, nil
}

type mechanismsFactory struct {
	r *mechanismRepository
}

func (hf *mechanismsFactory) CreateAuthenticator(_, id string, conf config.MechanismConfig) (
	authenticators.Authenticator, error,
) {
	prototype, err := hf.r.Authenticator(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
	}

	if conf != nil {
		authenticator, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrAuthenticatorCreation).CausedBy(err)
		}

		return authenticator, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateAuthorizer(_, id string, conf config.MechanismConfig) (
	authorizers.Authorizer, error,
) {
	prototype, err := hf.r.Authorizer(id)
	if err != nil {
		return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
	}

	if conf != nil {
		authorizer, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrAuthorizerCreation).CausedBy(err)
		}

		return authorizer, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateContextualizer(_, id string, conf config.MechanismConfig) (
	contextualizers.Contextualizer, error,
) {
	prototype, err := hf.r.Contextualizer(id)
	if err != nil {
		return nil, errorchain.New(ErrContextualizerCreation).CausedBy(err)
	}

	if conf != nil {
		contextualizer, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrContextualizerCreation).CausedBy(err)
		}

		return contextualizer, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateFinalizer(_, id string, conf config.MechanismConfig) (
	finalizers.Finalizer, error,
) {
	prototype, err := hf.r.Finalizer(id)
	if err != nil {
		return nil, errorchain.New(ErrFinalizerCreation).CausedBy(err)
	}

	if conf != nil {
		finalizer, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrFinalizerCreation).CausedBy(err)
		}

		return finalizer, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateErrorHandler(_, id string, conf config.MechanismConfig) (
	errorhandlers.ErrorHandler, error,
) {
	prototype, err := hf.r.ErrorHandler(id)
	if err != nil {
		return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
	}

	if conf != nil {
		errorHandler, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrErrorHandlerCreation).CausedBy(err)
		}

		return errorHandler, nil
	}

	return prototype, nil
}
