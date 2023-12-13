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

package errorhandlers

import (
	"errors"

	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func newBaseErrorHandler(id, conditionExpression string) (*baseErrorHandler, error) {
	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating CEL environment").CausedBy(err)
	}

	condition, err := cellib.CompileExpression(env, conditionExpression, "condition failed")
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to compile %s condition", conditionExpression).CausedBy(err)
	}

	return &baseErrorHandler{id: id, c: condition}, nil
}

type baseErrorHandler struct {
	id string
	c  *cellib.CompiledExpression
}

func (eh *baseErrorHandler) ID() string { return eh.id }

func (eh *baseErrorHandler) CanExecute(ctx heimdall.Context, cause error) bool {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", eh.id).Msg("Checking error handler applicability")

	err := eh.c.Eval(map[string]any{"Request": ctx.Request(), "Error": cellib.WrapError(cause)})
	if err != nil {
		if errors.Is(err, &cellib.EvalError{}) {
			logger.Debug().Err(err).Str("_id", eh.id).Msg("Error handler not applicable")
		} else {
			logger.Error().Err(err).Str("_id", eh.id).Msg("Failed checking error handler applicability")
		}

		return false
	}

	return true
}
