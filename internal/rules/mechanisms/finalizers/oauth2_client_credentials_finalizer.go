package finalizers

import (
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/oauth2/clientcredentials"
	"github.com/dadrus/heimdall/internal/x"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerOAuth2ClientCredentials {
				return false, nil, nil
			}

			finalizer, err := newOAuth2ClientCredentialsFinalizer(id, conf)

			return true, finalizer, err
		})
}

type oauth2ClientCredentialsFinalizer struct {
	id         string
	cfg        clientcredentials.Config
	headerName string
}

func newOAuth2ClientCredentialsFinalizer(
	id string,
	rawConfig map[string]any,
) (*oauth2ClientCredentialsFinalizer, error) {
	type Config struct {
		clientcredentials.Config `mapstructure:",squash"`
		Header                   *string `mapstructure:"header"  validate:"omitempty,gt=1"`
	}

	var conf Config
	if err := decodeConfig(FinalizerOAuth2ClientCredentials, rawConfig, &conf); err != nil {
		return nil, err
	}

	conf.AuthMethod = x.IfThenElse(
		len(conf.AuthMethod) == 0,
		clientcredentials.AuthMethodBasicAuth,
		clientcredentials.AuthMethodRequestBody,
	)

	return &oauth2ClientCredentialsFinalizer{
		id:  id,
		cfg: conf.Config,
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return *conf.Header },
			func() string { return "Authorization" }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) ContinueOnError() bool { return false }
func (f *oauth2ClientCredentialsFinalizer) ID() string            { return f.id }

func (f *oauth2ClientCredentialsFinalizer) WithConfig(rawConfig map[string]any) (Finalizer, error) {
	type Config struct {
		Scopes []string       `mapstructure:"scopes"`
		TTL    *time.Duration `mapstructure:"cache_ttl"`
		Header *string        `mapstructure:"header"    validate:"omitempty,gt=1"`
	}

	var conf Config
	if err := decodeConfig(FinalizerOAuth2ClientCredentials, rawConfig, &conf); err != nil {
		return nil, err
	}

	cfg := f.cfg
	cfg.TTL = x.IfThenElse(conf.TTL != nil, conf.TTL, cfg.TTL)
	cfg.Scopes = x.IfThenElse(conf.Scopes != nil, conf.Scopes, cfg.Scopes)

	return &oauth2ClientCredentialsFinalizer{
		id:  f.id,
		cfg: cfg,
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return *conf.Header },
			func() string { return f.headerName }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Finalizing using oauth2_client_credentials finalizer")

	token, err := f.cfg.Token(ctx.AppContext())
	if err != nil {
		return err
	}

	ctx.AddHeaderForUpstream(f.headerName, fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	return nil
}
