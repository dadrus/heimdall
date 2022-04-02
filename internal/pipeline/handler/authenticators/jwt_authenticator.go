package authenticators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type jwtAuthenticator struct {
	e   Endpoint
	a   oauth2.Expectation
	se  SubjectExtrator
	adg extractors.AuthDataExtractStrategy
}

func NewJwtAuthenticator(rawConfig map[string]any) (*jwtAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint                   `mapstructure:"jwks_endpoint"`
		AuthDataSource extractors.CompositeExtractStrategy `mapstructure:"jwt_token_from"`
		JwtAssertions  oauth2.Expectation                  `mapstructure:"jwt_assertions"`
		Session        Session                             `mapstructure:"session"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal jwt authenticator config").
			CausedBy(err)
	}

	if err := conf.JwtAssertions.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate assertions configuration").
			CausedBy(err)
	}

	if conf.Endpoint.Headers == nil {
		conf.Endpoint.Headers = make(map[string]string)
	}

	if _, ok := conf.Endpoint.Headers["Accept-Type"]; !ok {
		conf.Endpoint.Headers["Accept-Type"] = "application/json"
	}

	if len(conf.Endpoint.Method) == 0 {
		conf.Endpoint.Method = "GET"
	}

	if len(conf.JwtAssertions.AllowedAlgorithms) == 0 {
		conf.JwtAssertions.AllowedAlgorithms = []string{
			// ECDSA
			string(jose.ES256), string(jose.ES384), string(jose.ES512),
			// RSA-PSS
			string(jose.PS256), string(jose.PS384), string(jose.PS512),
		}
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if len(conf.Session.SubjectFrom) == 0 {
		conf.Session.SubjectFrom = "sub"
	}

	var adg extractors.AuthDataExtractStrategy
	if conf.AuthDataSource == nil {
		adg = extractors.CompositeExtractStrategy{
			extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
			extractors.FormParameterExtractStrategy{Name: "access_token"},
			extractors.QueryParameterExtractStrategy{Name: "access_token"},
		}
	} else {
		adg = conf.AuthDataSource
	}

	return &jwtAuthenticator{
		e:   conf.Endpoint,
		a:   conf.JwtAssertions,
		se:  &conf.Session,
		adg: adg,
	}, nil
}

func (a *jwtAuthenticator) Authenticate(
	ctx context.Context,
	as handler.RequestContext,
	sc *heimdall.SubjectContext,
) error {
	jwtRaw, err := a.adg.GetAuthData(as)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "not jwt token present").
			CausedBy(err)
	}

	// request jwks endpoint to verify jwt
	rawBody, err := a.e.SendRequest(ctx, nil)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to jwks endpoint failed").
			CausedBy(err)
	}

	// unmarshal the received key set
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received jwks").
			CausedBy(err)
	}

	rawClaims, err := a.verifyTokenAndGetClaims(jwtRaw, jwks)
	if err != nil {
		return err
	}

	if sc.Subject, err = a.se.GetSubject(rawClaims); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from jwt").
			CausedBy(err)
	}

	return nil
}

func (a *jwtAuthenticator) verifyTokenAndGetClaims(jwtRaw string, jwks jose.JSONWebKeySet) (json.RawMessage, error) {
	const jwtDotCount = 2
	if strings.Count(jwtRaw, ".") != jwtDotCount {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "unsupported jwt format")
	}

	token, err := jwt.ParseSigned(jwtRaw)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to parse jwt").
			CausedBy(err)
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
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no (unique) key found for the given key id").
			CausedBy(err)
	}

	if !a.a.IsAlgorithmAllowed(keys[0].Algorithm) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "%s algorithm is not allowed", keys[0].Algorithm)
	}

	var (
		mapClaims map[string]interface{}
		claims    oauth2.Claims
	)

	if err = token.Claims(&jwks, &mapClaims, &claims); err != nil {
		return nil, err
	}

	if err := claims.Validate(a.a); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			CausedBy(err)
	}

	rawPayload, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal jwt payload").
			CausedBy(err)
	}

	return rawPayload, nil
}

func (a *jwtAuthenticator) WithConfig(config map[string]any) (handler.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		JwtAssertions oauth2.Expectation `mapstructure:"jwt_assertions"`
	}

	var conf _config
	if err := mapstructure.Decode(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	return &jwtAuthenticator{
		e:   a.e,
		a:   conf.JwtAssertions,
		se:  a.se,
		adg: a.adg,
	}, nil
}
