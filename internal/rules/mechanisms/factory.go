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

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
)

var (
	ErrAuthenticatorCreation  = errors.New("failed to create authenticator")
	ErrAuthorizerCreation     = errors.New("failed to create authorizer")
	ErrFinalizerCreation      = errors.New("failed to create finalizer")
	ErrContextualizerCreation = errors.New("failed to create contextualizer")
	ErrErrorHandlerCreation   = errors.New("failed to create error handler")
)

//go:generate mockery --name Factory --structname FactoryMock

type Factory interface {
	CreateAuthenticator(version, id string, conf config.MechanismConfig) (authenticators.Authenticator, error)
	CreateAuthorizer(version, id string, conf config.MechanismConfig) (authorizers.Authorizer, error)
	CreateContextualizer(version, id string, conf config.MechanismConfig) (contextualizers.Contextualizer, error)
	CreateFinalizer(version, id string, conf config.MechanismConfig) (finalizers.Finalizer, error)
	CreateErrorHandler(version, id string, conf config.MechanismConfig) (errorhandlers.ErrorHandler, error)
}
