package authenticators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/config"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type authenticationDataAuthenticator struct {
	Endpoint         Endpoint
	SubjectExtractor SubjectExtrator
	AuthDataGetter   AuthDataGetter
}

func NewAuthenticationDataAuthenticatorFromJSON(rawConfig json.RawMessage) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint               `json:"identity_info_endpoint"`
		AuthDataSource config.AuthenticationDataSource `json:"authentication_data_source"`
		Session        config.Session                  `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to unmarshal config",
			Cause:   err,
		}
	}

	return &authenticationDataAuthenticator{
		Endpoint:         c.Endpoint,
		AuthDataGetter:   c.AuthDataSource.Strategy(),
		SubjectExtractor: &c.Session,
	}, nil
}

func (a *authenticationDataAuthenticator) Authenticate(ctx context.Context, as interfaces.AuthDataSource, sc *heimdall.SubjectContext) error {
	authDataRef, err := a.AuthDataGetter.GetAuthData(as)
	if err != nil {
		return &errorsx.ArgumentError{Message: "failed to extract authentication data", Cause: err}
	}

	rawBody, err := a.Endpoint.SendRequest(ctx, strings.NewReader(authDataRef))
	if err != nil {
		return err
	}

	if sc.Subject, err = a.SubjectExtractor.GetSubject(rawBody); err != nil {
		return err
	}

	return nil
}
