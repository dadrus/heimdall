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
	"reflect"

	"github.com/google/cel-go/cel"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type celExecutionCondition struct {
	p cel.Program
}

func (c *celExecutionCondition) CanExecute(ctx heimdall.Context, sub *subject.Subject, causeErr error) (bool, error) {
	obj := map[string]any{"Request": ctx.Request()}

	if sub != nil {
		obj["Subject"] = sub
	}

	if causeErr != nil {
		obj["Error"] = cellib.WrapError(causeErr)
	}

	out, _, err := c.p.Eval(obj)
	if err != nil {
		return false, err
	}

	return out.Value() == true, nil
}

func newCelExecutionCondition(expression string) (*celExecutionCondition, error) {
	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	ast, iss := env.Compile(expression)
	if iss != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed compiling cel expression").CausedBy(iss.Err())
	}

	if !reflect.DeepEqual(ast.OutputType(), cel.BoolType) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"result type error: wanted bool, got %v", ast.OutputType())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating cel program").CausedBy(err)
	}

	return &celExecutionCondition{p: prg}, nil
}
