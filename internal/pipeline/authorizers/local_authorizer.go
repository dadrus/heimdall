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
		func(_ string, typ config.PipelineObjectType, conf map[any]any) (bool, Authorizer, error) {
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

func newLocalAuthorizer(rawConfig map[any]any) (*localAuthorizer, error) {
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
	hmdl := vm.NewObject()

	if err := hmdl.Set("subject", sub); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to set subject for the heimdall object").
			CausedBy(err)
	}

	if err := hmdl.Set("ctx", ctx); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to set heimdall ctx for the heimdall object").
			CausedBy(err)
	}

	if err := vm.Set("heimdall", hmdl); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to set heimdall object for the script").
			CausedBy(err)
	}

	console := vm.NewObject()
	if err := console.Set("log", func(val string) {
		logger.Debug().Msg(val)
	}); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to set log function for the console object").
			CausedBy(err)
	}

	if err := vm.Set("console", console); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to set console object for the script").
			CausedBy(err)
	}

	if _, err := vm.RunProgram(a.p); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthorization, "script failed").
			CausedBy(err)
	}

	return nil
}

func (a *localAuthorizer) WithConfig(rawConfig map[any]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	return newLocalAuthorizer(rawConfig)
}
