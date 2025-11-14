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

package errorhandlers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindErrorHandler,
		ErrorHandlerDefault,
		registry.FactoryFunc(newDefaultErrorHandler),
	)
}

type defaultErrorHandler struct {
	name string
	id   string
}

func newDefaultErrorHandler(app app.Context, name string, _ map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", ErrorHandlerDefault).
		Str("_name", name).
		Msg("Creating error handler")

	return &defaultErrorHandler{
		name: name,
		id:   name,
	}, nil
}

func (eh *defaultErrorHandler) Execute(ctx heimdall.Context, _ identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", ErrorHandlerDefault).
		Str("_name", eh.name).
		Str("_id", eh.id).
		Msg("Executing error handler")

	return nil
}

func (eh *defaultErrorHandler) CreateStep(stepID string, rawConfig map[string]any) (heimdall.Step, error) {
	if len(stepID) == 0 && len(rawConfig) == 0 {
		return eh, nil
	}

	if len(rawConfig) == 0 {
		erh := *eh
		erh.id = stepID

		return &erh, nil
	}

	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
		"default error handler cannot be reconfigured")
}

func (eh *defaultErrorHandler) Kind() types.Kind { return types.KindErrorHandler }

func (eh *defaultErrorHandler) Name() string { return eh.name }

func (eh *defaultErrorHandler) ID() string { return eh.id }

func (eh *defaultErrorHandler) IsInsecure() bool { return false }
