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

	"github.com/dadrus/heimdall/internal/heimdall"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, _ map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerDefault {
				return false, nil, nil
			}

			return true, newDefaultErrorHandler(id), nil
		})
}

type defaultErrorHandler struct {
	id string
}

func newDefaultErrorHandler(id string) *defaultErrorHandler {
	return &defaultErrorHandler{id: id}
}

func (eh *defaultErrorHandler) CanExecute(_ heimdall.Context, _ error) bool { return true }

func (eh *defaultErrorHandler) Execute(ctx heimdall.Context, causeErr error) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", eh.id).Msg("Handling error using default error handler")

	ctx.SetPipelineError(causeErr)

	return nil
}

func (eh *defaultErrorHandler) WithConfig(_ map[string]any) (ErrorHandler, error) { return eh, nil }

func (eh *defaultErrorHandler) ID() string { return eh.id }
