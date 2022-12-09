package authorizers

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errCELResultType = errors.New("result type error")

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerCEL {
				return false, nil, nil
			}

			auth, err := newCELAuthorizer(id, conf)

			return true, auth, err
		})
}

type celAuthorizer struct {
	id    string
	env   *cel.Env
	rules []*celRule
}

type Rule struct {
	Value   string `mapstructure:"rule"`
	Message string `mapstructure:"message"`
}

func newCELAuthorizer(id string, rawConfig map[string]any) (*celAuthorizer, error) {
	type Config struct {
		Rules []Rule `mapstructure:"rules"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal CEL authorizer config").
			CausedBy(err)
	}

	if len(conf.Rules) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no rules provided for CEL authorizer")
	}

	env, err := cel.NewEnv(
		cel.Variable("subject", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	rules := make([]*celRule, len(conf.Rules))

	for i, rule := range conf.Rules {
		ast, err := compile(env, rule.Value)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile authorization rule %d (%s)", i+1, rule.Value).CausedBy(err)
		}

		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed creating program for authorization rule %d (%s)", i+1, rule.Value).CausedBy(err)
		}

		rules[i] = &celRule{
			m: x.IfThenElse(len(rule.Message) != 0, rule.Message, fmt.Sprintf("rule %d failed", i+1)),
			p: prg,
		}
	}

	return &celAuthorizer{id: id, env: env, rules: rules}, nil
}

func compile(env *cel.Env, expr string) (*cel.Ast, error) {
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

	return ast, nil
}

type celRule struct {
	m string
	p cel.Program
}

func (a *celAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using CEL authorizer")

	reqURL := ctx.RequestURL()

	obj := map[string]any{
		"subject": map[string]any{
			"id":         sub.ID,
			"attributes": sub.Attributes,
		},
		"request": map[string]any{
			"method": ctx.RequestMethod(),
			"url": map[string]any{
				"scheme": reqURL.Scheme,
				"host":   reqURL.Host,
				"path":   reqURL.Path,
				"query":  reqURL.Query(),
			},
			"client_ips": ctx.RequestClientIPs(),
			"headers":    ctx.RequestHeaders(),
		},
	}

	for _, rule := range a.rules {
		out, _, err := rule.p.Eval(obj)
		if err != nil {
			return errorchain.NewWithMessage(heimdall.ErrInternal, "failed evaluating rule").
				WithErrorContext(a).
				CausedBy(err)
		}

		if out.Value() != true {
			return errorchain.NewWithMessage(heimdall.ErrAuthorization, rule.m).
				WithErrorContext(a)
		}
	}

	return nil
}

func (a *celAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	return newCELAuthorizer(a.id, rawConfig)
}

func (a *celAuthorizer) HandlerID() string {
	return a.id
}
