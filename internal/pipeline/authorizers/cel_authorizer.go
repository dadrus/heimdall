package authorizers

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers/cellib"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

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
	id          string
	expressions []*Expression
}

func newCELAuthorizer(id string, rawConfig map[string]any) (*celAuthorizer, error) {
	type Config struct {
		Expressions []*Expression `mapstructure:"expressions"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal CEL authorizer config").
			CausedBy(err)
	}

	if len(conf.Expressions) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no expressions provided for CEL authorizer")
	}

	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	for i, expression := range conf.Expressions {
		err = expression.Compile(env)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile expression %d (%s)", i+1, expression.Value).CausedBy(err)
		}
	}

	return &celAuthorizer{id: id, expressions: conf.Expressions}, nil
}

func (a *celAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using CEL authorizer")

	obj := map[string]any{
		"Subject": sub,
		"Request": cellib.WrapRequest(ctx),
	}

	for i, expression := range a.expressions {
		ok, err := expression.Eval(obj)
		if err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed evaluating expression %d", i+1).
				WithErrorContext(a).
				CausedBy(err)
		}

		if !ok {
			return errorchain.NewWithMessage(heimdall.ErrAuthorization,
				x.IfThenElse(len(expression.Message) != 0, expression.Message,
					fmt.Sprintf("expression %d failed", i+1))).
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
