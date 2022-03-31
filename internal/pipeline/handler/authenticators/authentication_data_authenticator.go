package authenticators

import (
	"context"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type authenticationDataAuthenticator struct {
	e   Endpoint
	se  SubjectExtrator
	adg AuthDataGetter
}

func NewAuthenticationDataAuthenticatorFromYAML(rawConfig []byte) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint        `yaml:"identity_info_endpoint"`
		AuthDataSource authenticationDataSource `yaml:"authentication_data_source"`
		Session        Session                  `yaml:"session"`
	}

	var conf _config
	if err := yaml.UnmarshalStrict(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal authentication data authenticator config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if err := conf.Session.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate session configuration").
			CausedBy(err)
	}

	if conf.AuthDataSource.es == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no authentication_data_source configured")
	}

	return &authenticationDataAuthenticator{
		e:   conf.Endpoint,
		adg: conf.AuthDataSource.es,
		se:  &conf.Session,
	}, nil
}

func (a *authenticationDataAuthenticator) Authenticate(
	ctx context.Context,
	rc handler.RequestContext,
	sc *heimdall.SubjectContext,
) error {
	authDataRef, err := a.adg.GetAuthData(rc)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no authentication data present").
			CausedBy(err)
	}

	rawBody, err := a.e.SendRequest(ctx, strings.NewReader(authDataRef))
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to get information about the user failed").
			CausedBy(err)
	}

	if sc.Subject, err = a.se.GetSubject(rawBody); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			CausedBy(err)
	}

	return nil
}

func (a *authenticationDataAuthenticator) WithConfig(_ []byte) (handler.Authenticator, error) {
	// this authenticator does not allow configuration from a rule
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
