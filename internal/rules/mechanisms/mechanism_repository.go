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

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrNoSuchPipelineObject = errors.New("pipeline object not found")

func newMechanismRepository(app app.Context) (*mechanismRepository, error) {
	logger := app.Logger()
	conf := app.Config()

	logger.Debug().Msg("Loading definitions for authenticators")

	authenticatorMap, err := createPipelineObjects[authenticators.Authenticator](
		app, conf.Prototypes.Authenticators, authenticators.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authenticators definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for authorizers")

	authorizerMap, err := createPipelineObjects[authorizers.Authorizer](
		app, conf.Prototypes.Authorizers, authorizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading authorizers definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for contextualizer")

	contextualizerMap, err := createPipelineObjects[contextualizers.Contextualizer](
		app, conf.Prototypes.Contextualizers, contextualizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading contextualizer definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for finalizers")

	finalizerMap, err := createPipelineObjects[finalizers.Finalizer](
		app, conf.Prototypes.Finalizers, finalizers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading finalizer definitions")

		return nil, err
	}

	logger.Debug().Msg("Loading definitions for error handler")

	ehMap, err := createPipelineObjects[errorhandlers.ErrorHandler](
		app, conf.Prototypes.ErrorHandlers, errorhandlers.CreatePrototype)
	if err != nil {
		logger.Error().Err(err).Msg("Failed loading error handler definitions")

		return nil, err
	}

	return &mechanismRepository{
		authenticators:  authenticatorMap,
		authorizers:     authorizerMap,
		contextualizers: contextualizerMap,
		finalizers:      finalizerMap,
		errorHandlers:   ehMap,
	}, nil
}

func createPipelineObjects[T any](
	app app.Context,
	pObjects []config.Mechanism,
	create func(app app.Context, id string, typ string, c map[string]any) (T, error),
) (map[string]T, error) {
	objects := make(map[string]T)

	for _, pe := range pObjects {
		if len(pe.Condition) != 0 {
			pe.Config["if"] = pe.Condition
		}

		if r, err := create(app, pe.ID, pe.Type, pe.Config); err == nil {
			objects[pe.ID] = r
		} else {
			return nil, err
		}
	}

	return objects, nil
}

type mechanismRepository struct {
	authenticators  map[string]authenticators.Authenticator
	authorizers     map[string]authorizers.Authorizer
	contextualizers map[string]contextualizers.Contextualizer
	finalizers      map[string]finalizers.Finalizer
	errorHandlers   map[string]errorhandlers.ErrorHandler
}

func (r *mechanismRepository) Authenticator(id string) (authenticators.Authenticator, error) {
	authenticator, ok := r.authenticators[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no authenticator prototype for id='%s' found", id)
	}

	return authenticator, nil
}

func (r *mechanismRepository) Authorizer(id string) (authorizers.Authorizer, error) {
	authorizer, ok := r.authorizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no authorizer prototype for id='%s' found", id)
	}

	return authorizer, nil
}

func (r *mechanismRepository) Contextualizer(id string) (contextualizers.Contextualizer, error) {
	contextualizer, ok := r.contextualizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no contextualizer prototype for id='%s' found", id)
	}

	return contextualizer, nil
}

func (r *mechanismRepository) Finalizer(id string) (finalizers.Finalizer, error) {
	finalizer, ok := r.finalizers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no finalizer prototype for id='%s' found", id)
	}

	return finalizer, nil
}

func (r *mechanismRepository) ErrorHandler(id string) (errorhandlers.ErrorHandler, error) {
	errorHandler, ok := r.errorHandlers[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchPipelineObject,
			"no error handler prototype for id='%s' found", id)
	}

	return errorHandler, nil
}
