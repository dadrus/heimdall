// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package repository

import (
	"errors"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"  // registering authenticators
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"     // registering authorizers
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers" // registering contextualizers
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"   // registering error handlers
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"      // registering finalizers
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrMechanismNotFound = errors.New("mechanism not found")

func New(app app.Context) (types.Repository, error) {
	logger := app.Logger()
	conf := app.Config()
	repo := &repository{}

	logger.Info().Msg("Loading mechanism catalogue")

	for kind, definitions := range map[types.Kind][]config.Mechanism{
		types.KindAuthenticator:  conf.Catalogue.Authenticators,
		types.KindAuthorizer:     conf.Catalogue.Authorizers,
		types.KindContextualizer: conf.Catalogue.Contextualizers,
		types.KindFinalizer:      conf.Catalogue.Finalizers,
		types.KindErrorHandler:   conf.Catalogue.ErrorHandlers,
	} {
		logger.Debug().Msgf("Loading %s definitions", kind)

		objects, err := createMechanisms(app, kind, definitions)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed loading %s definitions", kind)

			return nil, err
		}

		switch kind {
		case types.KindAuthenticator:
			repo.authenticators = objects
		case types.KindAuthorizer:
			repo.authorizers = objects
		case types.KindContextualizer:
			repo.contextualizers = objects
		case types.KindFinalizer:
			repo.finalizers = objects
		case types.KindErrorHandler:
			repo.errorHandlers = objects
		}
	}

	return repo, nil
}

func createMechanisms(
	app app.Context,
	kind types.Kind,
	definitions []config.Mechanism,
) (map[string]types.Mechanism, error) {
	objects := make(map[string]types.Mechanism)

	for _, def := range definitions {
		mechanism, err := registry.Create(app, kind, def.Type, def.Name, def.Config)
		if err == nil {
			objects[def.Name] = mechanism
		} else {
			return nil, err
		}
	}

	return objects, nil
}

type repository struct {
	authenticators  map[string]types.Mechanism
	authorizers     map[string]types.Mechanism
	contextualizers map[string]types.Mechanism
	finalizers      map[string]types.Mechanism
	errorHandlers   map[string]types.Mechanism
}

func (r *repository) Authenticator(name string) (types.Mechanism, error) {
	authenticator, ok := r.authenticators[name]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrMechanismNotFound,
			"no authenticator mechanism definition for name='%s' found", name)
	}

	return authenticator, nil
}

func (r *repository) Authorizer(name string) (types.Mechanism, error) {
	authorizer, ok := r.authorizers[name]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrMechanismNotFound,
			"no authorizer mechanism definition for name='%s' found", name)
	}

	return authorizer, nil
}

func (r *repository) Contextualizer(name string) (types.Mechanism, error) {
	contextualizer, ok := r.contextualizers[name]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrMechanismNotFound,
			"no contextualizer mechanism definition for name='%s' found", name)
	}

	return contextualizer, nil
}

func (r *repository) Finalizer(name string) (types.Mechanism, error) {
	finalizer, ok := r.finalizers[name]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrMechanismNotFound,
			"no finalizer mechanism definition for name='%s' found", name)
	}

	return finalizer, nil
}

func (r *repository) ErrorHandler(name string) (types.Mechanism, error) {
	errorHandler, ok := r.errorHandlers[name]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrMechanismNotFound,
			"no error handler mechanism definition for name='%s' found", name)
	}

	return errorHandler, nil
}
