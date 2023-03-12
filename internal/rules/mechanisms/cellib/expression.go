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

type Expression struct {
	Value   string `mapstructure:"expression"`
	Message string `mapstructure:"message"`

	program cel.Program
}

func (e *Expression) Compile(env *cel.Env) error {
	ast, iss := env.Compile(e.Value)
	if iss.Err() != nil {
		return iss.Err()
	}

	ast, iss = env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}

	if !reflect.DeepEqual(ast.OutputType(), cel.BoolType) {
		return fmt.Errorf("%w: wanted bool, got %v", errCELResultType, ast.OutputType())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	e.program = prg

	return err
}

func (e *Expression) Eval(obj any) (bool, error) {
	out, _, err := e.program.Eval(obj)
	if err != nil {
		return false, err
	}

	return out.Value() == true, nil
}
