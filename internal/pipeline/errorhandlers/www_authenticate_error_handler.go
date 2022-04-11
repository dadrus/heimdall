package errorhandlers

import (
	"fmt"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers/matcher"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/rs/zerolog"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != config.POTWWWAuthenticate {
				return false, nil, nil
			}

			eh, err := newWWWAuthenticateErrorHandler(conf)

			return true, eh, err
		})
}

type wwwAuthenticateErrorHandler struct {
	realm string
	m     *matcher.ErrorConditionMatcher
}

func newWWWAuthenticateErrorHandler(rawConfig map[string]any) (*wwwAuthenticateErrorHandler, error) {
	type _config struct {
		Realm string                        `mapstructure:"realm"`
		When  matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if err := conf.When.Validate(); err != nil {
		return nil, err
	}

	return &wwwAuthenticateErrorHandler{
		realm: x.IfThenElse(len(conf.Realm) != 0, conf.Realm, "Please authenticate"),
		m:     &conf.When,
	}, nil
}

func (eh *wwwAuthenticateErrorHandler) HandleError(ctx heimdall.Context, err error) (bool, error) {
	if !eh.m.Match(ctx, err) {
		return false, nil
	}

	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling error using www-authenticate error handler")

	ctx.AddResponseHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%s", eh.realm))
	ctx.SetPipelineError(heimdall.ErrAuthentication)

	return true, nil
}

func (eh *wwwAuthenticateErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	type _config struct {
		Realm *string                        `mapstructure:"realm"`
		When  *matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"failed to unmarshal www authenticate error handler config").
			CausedBy(err)
	}

	if conf.Realm == nil && conf.When == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "either realm or when conditions must be set")
	}

	if conf.When != nil {
		if err := conf.When.Validate(); err != nil {
			return nil, err
		}
	}

	return &wwwAuthenticateErrorHandler{
		realm: x.IfThenElse(conf.Realm != nil, *conf.Realm, eh.realm),
		m:     x.IfThenElse(conf.When != nil, conf.When, eh.m),
	}, nil
}
