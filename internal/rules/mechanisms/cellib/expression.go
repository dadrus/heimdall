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

package cellib

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
)

var errCELResultType = errors.New("result type error")

func CompileExpression(env *cel.Env, expr, errMsg string) (*CompiledExpression, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}

	ast, iss = env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}

	if !reflect.DeepEqual(ast.OutputType(), cel.BoolType) {
		return nil, fmt.Errorf("%w: wanted bool, got %v", errCELResultType, ast.OutputType())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, err
	}

	return &CompiledExpression{p: prg, msg: errMsg}, nil
}

type EvalError struct {
	msg string
}

func (e *EvalError) Error() string { return e.msg }

func (e *EvalError) Is(err error) bool {
	ot := reflect.ValueOf(err).Elem().Type()
	mt := reflect.ValueOf(e).Elem().Type()

	return ot.AssignableTo(mt)
}

type CompiledExpression struct {
	msg string
	p   cel.Program
}

func (e *CompiledExpression) Eval(obj any) error {
	out, _, err := e.p.Eval(obj)
	if err != nil {
		return err
	}

	if out.Value() == true {
		return nil
	}

	return &EvalError{msg: e.msg}
}
