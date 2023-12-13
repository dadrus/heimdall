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

package authorizers

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Expression struct {
	Value   string `mapstructure:"expression" validate:"required"`
	Message string `mapstructure:"message"`
}

type compiledExpressions []*cellib.CompiledExpression

func (ce compiledExpressions) eval(obj, ctx any) error {
	for i, expression := range ce {
		err := expression.Eval(obj)
		if err != nil {
			if errors.Is(err, &cellib.EvalError{}) {
				return errorchain.New(heimdall.ErrAuthorization).CausedBy(err).WithErrorContext(ctx)
			}

			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed evaluating expression %d", i+1).
				CausedBy(err).WithErrorContext(ctx)
		}
	}

	return nil
}

func compileExpressions(expressions []Expression, env *cel.Env) (compiledExpressions, error) {
	compiled := make([]*cellib.CompiledExpression, len(expressions))

	for i, expression := range expressions {
		exp, err := cellib.CompileExpression(
			env,
			expression.Value,
			x.IfThenElse(len(expression.Message) != 0, expression.Message, fmt.Sprintf("expression %d failed", i+1)),
		)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile expression %d (%s)", i+1, expression.Value).CausedBy(err)
		}

		compiled[i] = exp
	}

	return compiled, nil
}
