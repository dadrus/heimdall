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

// nolint: revive
package types

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

type Kind string

const (
	KindAuthenticator  Kind = "authenticator"
	KindAuthorizer     Kind = "authorizer"
	KindContextualizer Kind = "contextualizer"
	KindFinalizer      Kind = "finalizer"
	KindErrorHandler   Kind = "error_handler"
)

type StepDefinition struct {
	ID        string
	Principal string
	Config    config.MechanismConfig
}

type Mechanism interface {
	Name() string
	Kind() Kind
	CreateStep(def StepDefinition) (heimdall.Step, error)
}
