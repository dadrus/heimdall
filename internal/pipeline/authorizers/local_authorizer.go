package authorizers

import (
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/script"
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
	s script.Script
}

func newLocalAuthorizer(rawConfig map[string]any) (*localAuthorizer, error) {
	type Config struct {
		Script script.Script `mapstructure:"script"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal local authorizer config").
			CausedBy(err)
	}

	if conf.Script == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no script provided for local authorizer")
	}

	return &localAuthorizer{s: conf.Script}, nil
}

func (a *localAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using local authorizer")

	res, err := a.s.Execute(ctx, sub)
	if err != nil {
		return errorchain.New(heimdall.ErrAuthorization).CausedBy(err)
	}

	if !res.ToBoolean() {
		return errorchain.NewWithMessage(heimdall.ErrAuthorization, "script failed")
	}

	return nil
}

func (a *localAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	return newLocalAuthorizer(rawConfig)
}
