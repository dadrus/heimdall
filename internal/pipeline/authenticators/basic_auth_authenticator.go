package authenticators

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	basicAuthSchemeCredentialsElements = 2
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(id string, typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTBasicAuth {
				return false, nil, nil
			}

			auth, err := newBasicAuthAuthenticator(id, conf)

			return true, auth, err
		})
}

type basicAuthAuthenticator struct {
	id                   string
	userID               string
	password             string
	allowFallbackOnError bool
}

func newBasicAuthAuthenticator(id string, rawConfig map[string]any) (*basicAuthAuthenticator, error) {
	type Config struct {
		UserID               string `mapstructure:"user_id"`
		Password             string `mapstructure:"password"`
		AllowFallbackOnError bool   `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config

	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode basic_auth authenticator config").
			CausedBy(err)
	}

	if len(conf.UserID) == 0 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "basic_auth authenticator requires user_id to be set")
	}

	if len(conf.Password) == 0 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "basic_auth authenticator requires password to be set")
	}

	auth := basicAuthAuthenticator{
		id:                   id,
		allowFallbackOnError: conf.AllowFallbackOnError,
	}

	// rewrite user id and password as hashes to mitigate potential side-channel attacks
	// during credentials check
	md := sha256.New()
	md.Write([]byte(conf.UserID))
	auth.userID = hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write([]byte(conf.Password))
	auth.password = hex.EncodeToString(md.Sum(nil))

	return &auth, nil
}

func (a *basicAuthAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using basic_auth authenticator")

	strategy := extractors.HeaderValueExtractStrategy{Name: "Authorization", Schema: "Basic"}

	authData, err := strategy.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "expected header not present in request").
			WithErrorContext(a).
			CausedBy(err)
	}

	res, err := base64.StdEncoding.DecodeString(authData.Value())
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to decode received credentials value").
			WithErrorContext(a)
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "malformed user-id - password scheme").
			WithErrorContext(a)
	}

	md := sha256.New()
	md.Write([]byte(userIDAndPassword[0]))
	userID := hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write([]byte(userIDAndPassword[1]))
	password := hex.EncodeToString(md.Sum(nil))

	userIDOK := userID == a.userID
	passwordOK := password == a.password

	if !(userIDOK && passwordOK) {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "invalid user credentials").
			WithErrorContext(a)
	}

	return &subject.Subject{ID: userIDAndPassword[0], Attributes: make(map[string]any)}, nil
}

func (a *basicAuthAuthenticator) WithConfig(rawConfig map[string]any) (Authenticator, error) {
	// this authenticator allows full redefinition on the rule level
	if len(rawConfig) == 0 {
		return a, nil
	}

	type Config struct {
		UserID               string `mapstructure:"user_id"`
		Password             string `mapstructure:"password"`
		AllowFallbackOnError *bool  `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config

	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode basic_auth authenticator config").
			CausedBy(err)
	}

	return &basicAuthAuthenticator{
		id: a.id,
		userID: x.IfThenElseExec(len(conf.UserID) != 0,
			func() string {
				md := sha256.New()
				md.Write([]byte(conf.UserID))

				return hex.EncodeToString(md.Sum(nil))
			}, func() string {
				return a.userID
			}),
		password: x.IfThenElseExec(len(conf.Password) != 0,
			func() string {
				md := sha256.New()
				md.Write([]byte(conf.Password))

				return hex.EncodeToString(md.Sum(nil))
			}, func() string {
				return a.password
			}),
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
	}, nil
}

func (a *basicAuthAuthenticator) IsFallbackOnErrorAllowed() bool {
	return a.allowFallbackOnError
}

func (a *basicAuthAuthenticator) HandlerID() string {
	return a.id
}
