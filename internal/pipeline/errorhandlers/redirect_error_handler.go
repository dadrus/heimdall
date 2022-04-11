package errorhandlers

import (
	"net/http"
	"net/url"

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
			if typ != config.POTRedirect {
				return false, nil, nil
			}

			eh, err := newRedirectErrorHandler(conf)

			return true, eh, err
		})
}

type redirectErrorHandler struct {
	to       *url.URL
	returnTo string
	code     int
	m        *matcher.ErrorConditionMatcher
}

func newRedirectErrorHandler(rawConfig map[string]any) (*redirectErrorHandler, error) {
	type _config struct {
		To       *url.URL                      `mapstructure:"to"`
		Code     int                           `mapstructure:"code"`
		ReturnTo string                        `mapstructure:"return_to_query_parameter"`
		When     matcher.ErrorConditionMatcher `mapstructure:"when"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal redirect error handler config").
			CausedBy(err)
	}

	if conf.To == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"redirect error handler requires 'to' parameter to be ser")
	}

	if err := conf.When.Validate(); err != nil {
		return nil, err
	}

	return &redirectErrorHandler{
		to:       conf.To,
		returnTo: conf.ReturnTo,
		code:     x.IfThenElse(conf.Code != 0, conf.Code, http.StatusFound),
		m:        &conf.When,
	}, nil
}

func (eh *redirectErrorHandler) HandleError(ctx heimdall.Context, err error) (bool, error) {
	if !eh.m.Match(ctx, err) {
		return false, nil
	}

	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Handling error using redirect error handler")

	toURL := *eh.to
	if len(eh.returnTo) != 0 {
		toQuery := toURL.Query()

		toQuery.Add(eh.returnTo, ctx.RequestURL().String())
		toURL.RawQuery = toQuery.Encode()
	}

	ctx.SetPipelineError(&heimdall.RedirectError{
		Message:    "redirect",
		Code:       eh.code,
		RedirectTo: &toURL,
	})

	return true, nil
}

func (eh *redirectErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	type _config struct {
		When matcher.ErrorConditionMatcher `mapstructure:"when"`
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

	return &redirectErrorHandler{
		to:       eh.to,
		returnTo: eh.returnTo,
		code:     eh.code,
		m:        &conf.When,
	}, nil
}
