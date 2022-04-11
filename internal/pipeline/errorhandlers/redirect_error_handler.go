package errorhandlers

import (
	"net/http"
	"net/url"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
	m        *ErrorConditionMatcher
}

func newRedirectErrorHandler(rawConfig map[string]any) (*redirectErrorHandler, error) {
	type _config struct {
		To       *url.URL              `mapstructure:"to"`
		Code     int                   `mapstructure:"code"`
		ReturnTo string                `mapstructure:"return_to_query_parameter"`
		When     ErrorConditionMatcher `mapstructure:"when"`
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

func (reh *redirectErrorHandler) HandleError(ctx heimdall.Context, err error) error {
	if !reh.m.Match(ctx, err) {
		return err
	}

	toURL := *reh.to
	if len(reh.returnTo) != 0 {
		toQuery := toURL.Query()

		toQuery.Add(reh.returnTo, ctx.RequestURL().String())
		toURL.RawQuery = toQuery.Encode()
	}

	ctx.SetPipelineError(&heimdall.RedirectError{
		Message:    "redirect",
		Code:       reh.code,
		RedirectTo: &toURL,
	})

	return nil
}

func (reh *redirectErrorHandler) WithConfig(rawConfig map[string]any) (ErrorHandler, error) {
	type _config struct {
		When ErrorConditionMatcher `mapstructure:"when"`
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
		to:       reh.to,
		returnTo: reh.returnTo,
		code:     reh.code,
		m:        &conf.When,
	}, nil
}
