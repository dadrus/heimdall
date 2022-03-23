package authenticators

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dadrus/heimdall/config"
	"github.com/dadrus/heimdall/endpoint"
	"github.com/dadrus/heimdall/extractors"
	"github.com/dadrus/heimdall/pipeline"
)

var _ Authenticator = new(authenticationDataAuthenticator)

func newAuthenticationDataAuthenticator(rawConfig json.RawMessage) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint               `json:"identity_info_endpoint"`
		AuthDataSource config.AuthenticationDataSource `json:"authentication_data_source"`
		Session        config.Session                  `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	return &authenticationDataAuthenticator{
		e:  c.Endpoint,
		ae: c.AuthDataSource.Strategy(),
		se: c.Session,
	}, nil
}

type authenticationDataAuthenticator struct {
	e  endpoint.Endpoint
	se config.Session
	ae extractors.AuthDataExtractStrategy
}

func (a *authenticationDataAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	authDataRef, err := a.ae.GetAuthData(as)
	if err != nil {
		return fmt.Errorf("failed to extract authentication data: %w", err)
	}

	rawBody, err := a.e.SendRequest(ctx, strings.NewReader(authDataRef))
	if err != nil {
		return err
	}

	if sc.Subject, err = a.se.GetSubject(rawBody); err != nil {
		return err
	}

	return nil
}
