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

package rules

import (
	"errors"

	"github.com/google/cel-go/cel"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type celExecutionCondition struct {
	e *cellib.CompiledExpression
}

func (c *celExecutionCondition) CanExecute(ctx heimdall.Context, sub subject.Subject) (bool, error) {
	obj := map[string]any{"Request": ctx.Request()}

	if len(sub) != 0 {
		obj["Subject"] = sub["Subject"]
	}

	if err := c.e.Eval(obj); err != nil {
		if errors.Is(err, &cellib.EvalError{}) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func newCelExecutionCondition(expression string) (*celExecutionCondition, error) {
	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	expr, err := cellib.CompileExpression(env, expression, "expression evaluated to false")
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed compiling cel expression").CausedBy(err)
	}

	return &celExecutionCondition{e: expr}, nil
}
