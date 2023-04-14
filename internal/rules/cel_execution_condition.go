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

func (c *celExecutionCondition) CanExecute(ctx heimdall.Context, sub *subject.Subject) (bool, error) {
	obj := map[string]any{
		"Subject": sub,
		"Request": cellib.WrapRequest(ctx),
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
