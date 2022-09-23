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
		func(id string, typ config.PipelineObjectType, conf map[string]any) (bool, Authorizer, error) {
			if typ != config.POTLocal {
				return false, nil, nil
			}

			auth, err := newLocalAuthorizer(id, conf)

			return true, auth, err
		})
}

type localAuthorizer struct {
	id string
	s  script.Script
}

func newLocalAuthorizer(id string, rawConfig map[string]any) (*localAuthorizer, error) {
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

	return &localAuthorizer{id: id, s: conf.Script}, nil
}

func (a *localAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using local authorizer")

	res, err := a.s.ExecuteOnSubject(ctx, sub)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrAuthorization, "script failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	if !res.ToBoolean() {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthorization, "script failed").
			WithErrorContext(a)
	}

	return nil
}

func (a *localAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	return newLocalAuthorizer(a.id, rawConfig)
}

func (a *localAuthorizer) HandlerID() string {
	return a.id
}
