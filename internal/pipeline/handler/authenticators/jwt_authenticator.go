package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type jwtAuthenticator struct {
	Endpoint         Endpoint
	Assertions       oauth2.Assertions
	SubjectExtractor SubjectExtrator
	AuthDataGetter   AuthDataGetter
}

func NewJwtAuthenticatorFromJSON(rawConfig json.RawMessage) (*jwtAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint        `json:"jwks_endpoint"`
		AuthDataSource AuthenticationDataSource `json:"jwt_token_from"`
		Assertions     oauth2.Assertions        `json:"jwt_assertions"`
		Session        Session                  `json:"session"`
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

	return &jwtAuthenticator{
		Endpoint:         c.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: &c.Session,
		AuthDataGetter:   c.AuthDataSource.Strategy(),
	}, nil
}

func (a *jwtAuthenticator) Authenticate(ctx context.Context, as handler.AuthDataSource, sc *heimdall.SubjectContext) error {
	// request jwks endpoint to verify jwt
	rawBody, err := a.Endpoint.SendRequest(ctx, nil)
	if err != nil {
		return err
	}

	// unmarshal the received key set
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		return err
	}

	jwtRaw, err := a.AuthDataGetter.GetAuthData(as)
	if err != nil {
		return &errorsx.ArgumentError{Message: "no jwt present", Cause: err}
	}

	rawClaims, err := a.verifyTokenAndGetClaims(jwtRaw, jwks)
	if err != nil {
		return err
	}

	if sc.Subject, err = a.SubjectExtractor.GetSubject(rawClaims); err != nil {
		return err
	}

	return nil
}

func (a *jwtAuthenticator) verifyTokenAndGetClaims(jwtRaw string, jwks jose.JSONWebKeySet) (json.RawMessage, error) {
	var (
		token *jwt.JSONWebToken
		err   error
	)

	delims := strings.Count(jwtRaw, ".")
	if delims == 2 {
		token, err = jwt.ParseSigned(jwtRaw)
	} else if delims == 3 {
		nestedToken, err := jwt.ParseSignedAndEncrypted(jwtRaw)
		if err != nil {
			return nil, err
		}
		token, err = nestedToken.Decrypt(&jwks)
	} else {
		return nil, errors.New("invalid jwt format")
	}

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

	if !a.Assertions.IsAlgorithmAllowed(keys[0].Algorithm) {
		return nil, fmt.Errorf("%s algorithm is not allowed", keys[0].Algorithm)
	}

	var payload oauth2.JwtPayload
	var tokenClaims map[string]interface{}
	if err = token.Claims(&jwks, &tokenClaims, &payload); err != nil {
		return nil, err
	}

	if err = payload.Verify(a.Assertions); err != nil {
		return nil, err
	}

	rawPayload, err := json.Marshal(tokenClaims)
	if err != nil {
		return nil, err
	}

	return rawPayload, nil
}

func (a *jwtAuthenticator) WithConfig(config json.RawMessage) (handler.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		Assertions oauth2.Assertions `json:"jwt_assertions"`
	}

	var c _config
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, err
	}

	return &jwtAuthenticator{
		Endpoint:         a.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: a.SubjectExtractor,
		AuthDataGetter:   a.AuthDataGetter,
	}, nil
}
