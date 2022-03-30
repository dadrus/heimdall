package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jwtAuthenticator struct {
	e   Endpoint
	a   oauth2.Expectation
	se  SubjectExtrator
	adg AuthDataGetter
}

func NewJwtAuthenticatorFromYAML(rawConfig []byte) (*jwtAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint        `yaml:"jwks_endpoint"`
		AuthDataSource authenticationDataSource `yaml:"jwt_token_from"`
		JwtAssertions  oauth2.Expectation       `yaml:"jwt_assertions"`
		Session        Session                  `yaml:"session"`
	}

	var c _config
	if err := yaml.UnmarshalStrict(rawConfig, &c); err != nil {
		return nil, err
	}

	if err := c.JwtAssertions.Validate(); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to validate assertions configuration",
			Cause:   err,
		}
	}

	if c.Endpoint.Headers == nil {
		c.Endpoint.Headers = make(map[string]string)
	}

	if _, ok := c.Endpoint.Headers["Accept-Type"]; !ok {
		c.Endpoint.Headers["Accept-Type"] = "application/json"
	}
	if len(c.Endpoint.Method) == 0 {
		c.Endpoint.Method = "GET"
	}

	if len(c.JwtAssertions.AllowedAlgorithms) == 0 {
		c.JwtAssertions.AllowedAlgorithms = []string{
			// ECDSA
			string(jose.ES256), string(jose.ES384), string(jose.ES512),
			// RSA-PSS
			string(jose.PS256), string(jose.PS384), string(jose.PS512),
		}
	}

	if err := c.Endpoint.Validate(); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to validate endpoint configuration",
			Cause:   err,
		}
	}

	if len(c.Session.SubjectFrom) == 0 {
		c.Session.SubjectFrom = "sub"
	}

	var adg extractors.AuthDataExtractStrategy
	if c.AuthDataSource.es == nil {
		adg = extractors.CompositeExtractStrategy{
			extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
			extractors.FormParameterExtractStrategy{Name: "access_token"},
			extractors.QueryParameterExtractStrategy{Name: "access_token"},
		}
	} else {
		adg = c.AuthDataSource.es
	}

	return &jwtAuthenticator{
		e:   c.Endpoint,
		a:   c.JwtAssertions,
		se:  &c.Session,
		adg: adg,
	}, nil
}

func (a *jwtAuthenticator) Authenticate(ctx context.Context, as handler.RequestContext, sc *heimdall.SubjectContext) error {
	// request jwks endpoint to verify jwt
	rawBody, err := a.e.SendRequest(ctx, nil)
	if err != nil {
		return err
	}

	// unmarshal the received key set
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		return err
	}

	jwtRaw, err := a.adg.GetAuthData(as)
	if err != nil {
		return &errorsx.ArgumentError{Message: "no jwt present", Cause: err}
	}

	rawClaims, err := a.verifyTokenAndGetClaims(jwtRaw, jwks)
	if err != nil {
		return err
	}

	if sc.Subject, err = a.se.GetSubject(rawClaims); err != nil {
		return err
	}

	return nil
}

func (a *jwtAuthenticator) verifyTokenAndGetClaims(jwtRaw string, jwks jose.JSONWebKeySet) (json.RawMessage, error) {
	if strings.Count(jwtRaw, ".") != 2 {
		return nil, errors.New("unsupported jwt format")
	}

	token, err := jwt.ParseSigned(jwtRaw)
	if err != nil {
		return nil, err
	}

	var keys []jose.JSONWebKey
	for _, h := range token.Headers {
		keys = jwks.Key(h.KeyID)
		if len(keys) != 0 {
			break
		}
	}
	// even the spec allows for multiple keys for the given id, we do not
	if len(keys) != 1 {
		return nil, errors.New("no (unique) key found for the given key id")
	}

	if !a.a.IsAlgorithmAllowed(keys[0].Algorithm) {
		return nil, fmt.Errorf("%s algorithm is not allowed", keys[0].Algorithm)
	}

	var mapClaims map[string]interface{}
	var claims oauth2.Claims
	if err = token.Claims(&jwks, &mapClaims, &claims); err != nil {
		return nil, err
	}

	if err := claims.Validate(a.a); err != nil {
		return nil, &errorsx.UnauthorizedError{
			Message: "access token does not satisfy assertion conditions",
			Cause:   err,
		}
	}

	rawPayload, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, err
	}

	return rawPayload, nil
}

func (a *jwtAuthenticator) WithConfig(config []byte) (handler.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		JwtAssertions oauth2.Expectation `yaml:"jwt_assertions"`
	}

	var c _config
	if err := yaml.Unmarshal(config, &c); err != nil {
		return nil, err
	}

	return &jwtAuthenticator{
		e:   a.e,
		a:   c.JwtAssertions,
		se:  a.se,
		adg: a.adg,
	}, nil
}
