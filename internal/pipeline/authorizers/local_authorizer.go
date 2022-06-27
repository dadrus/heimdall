package authorizers

import (
	"github.com/dop251/goja"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[string]any) (bool, Authorizer, error) {
			if typ != config.POTLocal {
				return false, nil, nil
			}

			auth, err := newLocalAuthorizer(conf)

			return true, auth, err
		})
}

type localAuthorizer struct {
	p *goja.Program
}

func newLocalAuthorizer(rawConfig map[string]any) (*localAuthorizer, error) {
	type _config struct {
		Script string `mapstructure:"script"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal local authorizer config").
			CausedBy(err)
	}

	if len(conf.Script) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no script provided for local authorizer")
	}

	programm, err := goja.Compile("", conf.Script, true)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to compile provided script").
			CausedBy(err)
	}

	return &localAuthorizer{p: programm}, nil
}

func (a *localAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using local authorizer")

	vm := goja.New()

	// the error checks below are ignored by intention as these cannot happen here
	// we can also not test the corresponding occurrence and if these would happen
	// the script execution would result in an error anyway, which basically means
	// failed authorization, which also would happen if any of these errors would
	// happen.

	hmdl := vm.NewObject()
	// nolint: errcheck
	hmdl.Set("Subject", sub)
	// nolint: errcheck
	hmdl.Set("RequestMethod", func() string {
		return ctx.RequestMethod()
	})
	// nolint: errcheck
	hmdl.Set("RequestURL", func() string {
		return ctx.RequestURL().String()
	})
	// nolint: errcheck
	hmdl.Set("RequestClientIPs", func() []string {
		return ctx.RequestClientIPs()
	})
	// nolint: errcheck
	hmdl.Set("RequestHeader", func(name string) string {
		return ctx.RequestHeader(name)
	})
	// nolint: errcheck
	hmdl.Set("RequestCookie", func(name string) string {
		return ctx.RequestCookie(name)
	})
	// nolint: errcheck
	hmdl.Set("RequestQueryParameter", func(name string) string {
		return ctx.RequestQueryParameter(name)
	})

	console := vm.NewObject()
	// nolint: errcheck
	console.Set("log", func(val string) { logger.Debug().Msg(val) })

	// nolint: errcheck
	vm.Set("heimdall", hmdl)
	// nolint: errcheck
	vm.Set("console", console)

	if _, err := vm.RunProgram(a.p); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthorization, "script failed").
			CausedBy(err)
	}

	return nil
}

func (a *localAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	return newLocalAuthorizer(rawConfig)
}
