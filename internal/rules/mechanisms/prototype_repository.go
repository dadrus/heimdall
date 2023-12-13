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
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrNoSuchPipelineObject = errors.New("pipeline object not found")

func newPrototypeRepository(
	conf *config.Configuration,
	logger zerolog.Logger,
) (*prototypeRepository, error) {
	logger.Debug().Msg("Loading definitions for authenticators")

	authenticatorMap, err := createPipelineObjects(conf.Prototypes.Authenticators, logger,
		authenticators.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authenticators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for authorizers")

	authorizerMap, err := createPipelineObjects(conf.Prototypes.Authorizers, logger,
		authorizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authorizers definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for contextualizer")

	contextualizerMap, err := createPipelineObjects(conf.Prototypes.Contextualizers, logger,
		contextualizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading contextualizer definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for finalizers")

	finalizerMap, err := createPipelineObjects(conf.Prototypes.Finalizers, logger,
		finalizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading finalizer definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for error handler")

	ehMap, err := createPipelineObjects(conf.Prototypes.ErrorHandlers, logger,
		errorhandlers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading error handler definitions")

		return nil, err
	}

	return &prototypeRepository{
		authenticators:  authenticatorMap,
		authorizers:     authorizerMap,
		contextualizers: contextualizerMap,
		finalizers:      finalizerMap,
		errorHandlers:   ehMap,
	}, nil
}

func createPipelineObjects[T any](
	pObjects []config.Mechanism,
	logger zerolog.Logger,
	create func(id string, typ string, c map[string]any) (T, error),
) (map[string]T, error) {
	objects := make(map[string]T)

	for _, pe := range pObjects {
		logger.Debug().Str("_id", pe.ID).Str("_type", pe.Type).Msg("Loading pipeline definition")

		if len(pe.Condition) != 0 {
			pe.Config["if"] = pe.Condition
		}

		if r, err := create(pe.ID, pe.Type, pe.Config); err == nil {
			objects[pe.ID] = r
		} else {
			return nil, err
		}
	}

	return objects, nil
}

type prototypeRepository struct {
	authenticators  map[string]authenticators.Authenticator
	authorizers     map[string]authorizers.Authorizer
	contextualizers map[string]contextualizers.Contextualizer
	finalizers      map[string]finalizers.Finalizer
	errorHandlers   map[string]errorhandlers.ErrorHandler
}

func (r *prototypeRepository) Authenticator(id string) (authenticators.Authenticator, error) {
	authenticator, ok := r.authenticators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no authenticator prototype for id='%s' found", id)
	}

	return authenticator, nil
}

func (r *prototypeRepository) Authorizer(id string) (authorizers.Authorizer, error) {
	authorizer, ok := r.authorizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no authorizer prototype for id='%s' found", id)
	}

	return authorizer, nil
}

func (r *prototypeRepository) Contextualizer(id string) (contextualizers.Contextualizer, error) {
	contextualizer, ok := r.contextualizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no contextualizer prototype for id='%s' found", id)
	}

	return contextualizer, nil
}

func (r *prototypeRepository) Finalizer(id string) (finalizers.Finalizer, error) {
	finalizer, ok := r.finalizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no finalizer prototype for id='%s' found", id)
	}

	return finalizer, nil
}

func (r *prototypeRepository) ErrorHandler(id string) (errorhandlers.ErrorHandler, error) {
	errorHandler, ok := r.errorHandlers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no error handler prototype for id='%s' found", id)
	}

	return errorHandler, nil
}
