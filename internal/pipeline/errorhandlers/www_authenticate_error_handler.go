package errorhandlers

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers/matcher"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(_ string, typ config.PipelineHandlerType, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != config.POTWWWAuthenticate {
				return false, nil, nil
			}

			eh, err := newWWWAuthenticateErrorHandler(conf)

			return true, eh, err
		})
}

type wwwAuthenticateErrorHandler struct {
	realm string
	m     []matcher.ErrorConditionMatcher
}

func newWWWAuthenticateErrorHandler(rawConfig map[string]any) (*wwwAuthenticateErrorHandler, error) {
	type Config struct {
		Realm string                          `mapstructure:"realm"`
		When  []matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if len(conf.When) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no 'when' error handler conditions defined for the www-authenticate error handler")
	}

	return &wwwAuthenticateErrorHandler{
		realm: x.IfThenElse(len(conf.Realm) != 0, conf.Realm, "Please authenticate"),
		m:     conf.When,
	}, nil
}

func (eh *wwwAuthenticateErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	for _, ecm := range eh.m {
		if !ecm.Match(ctx, err) {
			return false, nil
		}
	}

	logger.Debug().Msg("Handling error using www-authenticate error handler")

	ctx.AddHeaderForUpstream("WWW-Authenticate", fmt.Sprintf("Basic realm=%s", eh.realm))
	ctx.SetPipelineError(heimdall.ErrAuthentication)

	return true, nil
}

func (eh *wwwAuthenticateErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	if len(rawConfig) == 0 {
		return eh, nil
	}

	type Config struct {
		Realm *string                          `mapstructure:"realm"`
		When  *[]matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"failed to unmarshal www authenticate error handler config").
			CausedBy(err)
	}

	return &wwwAuthenticateErrorHandler{
		realm: x.IfThenElseExec(conf.Realm != nil,
			func() string { return *conf.Realm },
			func() string { return eh.realm }),
		m: x.IfThenElseExec(conf.When != nil,
			func() []matcher.ErrorConditionMatcher { return *conf.When },
			func() []matcher.ErrorConditionMatcher { return eh.m },
		),
	}, nil
}
