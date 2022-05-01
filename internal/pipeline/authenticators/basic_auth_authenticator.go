package authenticators

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	basicAuthSchemeAttributes          = 2
	basicAuthSchemeCredentialsElements = 2
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[any]any) (bool, Authenticator, error) {
			if typ != config.POTBasicAuth {
				return false, nil, nil
			}

			auth, err := newBasicAuthAuthenticator(conf)

			return true, auth, err
		})
}

type basicAuthAuthenticator struct {
	UserID   string `mapstructure:"user_id"`
	Password string `mapstructure:"password"`
}

func newBasicAuthAuthenticator(rawConfig map[any]any) (*basicAuthAuthenticator, error) {
	var auth basicAuthAuthenticator

	if err := decodeConfig(rawConfig, &auth); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode basic_auth authenticator config").
			CausedBy(err)
	}

	if len(auth.UserID) == 0 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "basic_auth authenticator requires user_id to be set")
	}

	if len(auth.Password) == 0 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "basic_auth authenticator requires password to be set")
	}

	// rewrite user id and password as hashes to mitigate potential side-channel attacks
	// during credentials check
	md := sha256.New()
	md.Write([]byte(auth.UserID))
	auth.UserID = hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write([]byte(auth.Password))
	auth.Password = hex.EncodeToString(md.Sum(nil))

	return &auth, nil
}

func (a *basicAuthAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using basic_auth authenticator")

	headerValue := ctx.RequestHeader("Authorization")
	if len(headerValue) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no Authorization header received")
	}

	schemeAndValue := strings.Split(headerValue, " ")
	if len(schemeAndValue) != basicAuthSchemeAttributes {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "unexpected value in the Authorization header")
	}

	if schemeAndValue[0] != "Basic" {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "unexpected authentication scheme: %s", schemeAndValue[0])
	}

	res, err := base64.StdEncoding.DecodeString(schemeAndValue[1])
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to decode received credentials value")
	}

	userIDAndPassword := strings.Split(string(res), ":")
	if len(userIDAndPassword) != basicAuthSchemeCredentialsElements {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "malformed user-id - password scheme")
	}

	md := sha256.New()
	md.Write([]byte(userIDAndPassword[0]))
	userID := hex.EncodeToString(md.Sum(nil))

	md.Reset()
	md.Write([]byte(userIDAndPassword[1]))
	password := hex.EncodeToString(md.Sum(nil))

	userIDOK := userID == a.UserID
	passwordOK := password == a.Password

	if !(userIDOK && passwordOK) {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "invalid user credentials")
	}

	return &subject.Subject{ID: userIDAndPassword[0], Attributes: make(map[string]any)}, nil
}

func (a *basicAuthAuthenticator) WithConfig(config map[any]any) (Authenticator, error) {
	// this authenticator allows full redefinition on the rule level
	if len(config) == 0 {
		return a, nil
	}

	return newBasicAuthAuthenticator(config)
}
