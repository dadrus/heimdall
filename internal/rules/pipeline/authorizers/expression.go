package authorizers

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
