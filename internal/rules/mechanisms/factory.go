// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/unifiers"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrAuthenticatorCreation  = errors.New("failed to create authenticator")
	ErrAuthorizerCreation     = errors.New("failed to create authorizer")
	ErrUnifierCreation        = errors.New("failed to create unifier")
	ErrContextualizerCreation = errors.New("failed to create contextualizer")
	ErrErrorHandlerCreation   = errors.New("failed to create error handler")
)

//go:generate mockery --name Factory --structname FactoryMock

type Factory interface {
	CreateAuthenticator(id string, conf config.MechanismConfig) (authenticators.Authenticator, error)
	CreateAuthorizer(id string, conf config.MechanismConfig) (authorizers.Authorizer, error)
	CreateContextualizer(id string, conf config.MechanismConfig) (contextualizers.Contextualizer, error)
	CreateUnifier(id string, conf config.MechanismConfig) (unifiers.Unifier, error)
	CreateErrorHandler(id string, conf config.MechanismConfig) (errorhandlers.ErrorHandler, error)
}

func NewFactory(conf *config.Configuration, logger zerolog.Logger) (Factory, error) {
	logger.Info().Msg("Loading pipeline definitions")

	repository, err := newPrototypeRepository(conf, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading pipeline definitions")

		return nil, err
	}

	return &mechanismsFactory{r: repository}, nil
}

type mechanismsFactory struct {
	r *prototypeRepository
}

func (hf *mechanismsFactory) CreateAuthenticator(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateAuthorizer(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateContextualizer(id string, conf config.MechanismConfig) (
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

func (hf *mechanismsFactory) CreateUnifier(id string, conf config.MechanismConfig) (
	unifiers.Unifier, error,
) {
	prototype, err := hf.r.Unifier(id)
	if err != nil {
		return nil, errorchain.New(ErrUnifierCreation).CausedBy(err)
	}

	if conf != nil {
		unifier, err := prototype.WithConfig(conf)
		if err != nil {
			return nil, errorchain.New(ErrUnifierCreation).CausedBy(err)
		}

		return unifier, nil
	}

	return prototype, nil
}

func (hf *mechanismsFactory) CreateErrorHandler(id string, conf config.MechanismConfig) (
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
