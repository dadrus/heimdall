package repositories

import (
	"encoding/json"

	"github.com/dadrus/heimdall/authenticators"
	"github.com/dadrus/heimdall/config"
	"github.com/dadrus/heimdall/endpoint"
	"github.com/dadrus/heimdall/errorsx"
	"github.com/dadrus/heimdall/extractors"
	"github.com/dadrus/heimdall/oauth2"
)

func NewAnonymousAuthenticatorFromJSON(rawConfig json.RawMessage) (*authenticators.AnonymousAuthenticator, error) {
	var authenticator authenticators.AnonymousAuthenticator

	if err := json.Unmarshal(rawConfig, &authenticator); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to unmarshal config",
			Cause:   err,
		}
	}

	return &authenticator, nil
}

func NewAuthenticationDataAuthenticatorFromJSON(rawConfig json.RawMessage) (*authenticators.AuthenticationDataAuthenticator, error) {
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

	return &authenticators.AuthenticationDataAuthenticator{
		Endpoint:         c.Endpoint,
		AuthDataGetter:   c.AuthDataSource.Strategy(),
		SubjectExtractor: &c.Session,
	}, nil
}

func NewJwtAuthenticatorFromJSON(rawConfig json.RawMessage) (*authenticators.JwtAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint               `json:"jwks_endpoint"`
		AuthDataSource config.AuthenticationDataSource `json:"jwt_token_from"`
		Assertions     oauth2.Assertions               `json:"jwt_assertions"`
		Session        config.Session                  `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	if _, ok := c.Endpoint.Headers["Accept-Type"]; !ok {
		c.Endpoint.Headers["Accept-Type"] = "application/json"
	}
	if len(c.Endpoint.Method) == 0 {
		c.Endpoint.Method = "GET"
	}

	return &authenticators.JwtAuthenticator{
		Endpoint:         c.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: &c.Session,
		AuthDataGetter:   c.AuthDataSource.Strategy(),
	}, nil
}

func NewOAuth2IntrospectionAuthenticatorFromJSON(rawConfig json.RawMessage) (*authenticators.OAuth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint   endpoint.Endpoint `json:"introspection_endpoint"`
		Assertions oauth2.Assertions `json:"introspection_response_assertions"`
		Session    config.Session    `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	c.Endpoint.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	c.Endpoint.Headers["Accept-Type"] = "application/json"

	extractor := extractors.CompositeExtractStrategy{
		extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
		extractors.FormParameterExtractStrategy{Name: "access_token"},
		extractors.QueryParameterExtractStrategy{Name: "access_token"},
	}

	return &authenticators.OAuth2IntrospectionAuthenticator{
		AuthDataGetter:   extractor,
		Endpoint:         c.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: &c.Session,
	}, nil
}
