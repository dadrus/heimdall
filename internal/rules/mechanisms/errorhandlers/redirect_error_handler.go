package errorhandlers

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/matcher"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerErrorHandlerTypeFactory(
		func(_ string, typ string, conf map[string]any) (bool, ErrorHandler, error) {
			if typ != ErrorHandlerRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct {
	to   template.Template
	code int
	m    []matcher.ErrorConditionMatcher
}

func newRedirectErrorHandler(rawConfig map[string]any) (*redirectErrorHandler, error) {
	type Config struct {
		To   template.Template               `mapstructure:"to"`
		Code int                             `mapstructure:"code"`
		When []matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if conf.To == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"redirect error handler requires 'to' parameter to be set")
	}

	if len(conf.When) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"no 'when' error handler conditions defined for the redirect error handler")
	}

	return &redirectErrorHandler{
		to:   conf.To,
		code: x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
		m:    conf.When,
	}, nil
}

func (eh *redirectErrorHandler) Execute(ctx heimdall.Context, err error) (bool, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	for _, ecm := range eh.m {
		if !ecm.Match(ctx, err) {
			return false, nil
		}
	}

	logger.Debug().Msg("Handling error using redirect error handler")

	toURL, err := eh.to.Render(ctx, nil)
	if err != nil {
		return true, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to render 'to' url").
			CausedBy(err)
	}

	ctx.SetPipelineError(&heimdall.RedirectError{
		Message:    "redirect",
		Code:       eh.code,
		RedirectTo: toURL,
	})

	return true, nil
}

func (eh *redirectErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	if len(rawConfig) == 0 {
		return eh, nil
	}

	type Config struct {
		When []matcher.ErrorConditionMatcher `mapstructure:"when"`
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
				"no error handler conditions defined for the redirect error handler")
	}

	return &redirectErrorHandler{
		to:   eh.to,
		code: eh.code,
		m:    conf.When,
	}, nil
}
