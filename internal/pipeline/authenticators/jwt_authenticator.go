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
	"github.com/dadrus/heimdall/internal/pipeline"
)

type JwtAuthenticator struct {
	Endpoint         Endpoint
	Assertions       oauth2.Assertions
	SubjectExtractor SubjectExtrator
	AuthDataGetter   AuthDataGetter
}

func (a *JwtAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *heimdall.SubjectContext) error {
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

func (a *JwtAuthenticator) verifyTokenAndGetClaims(jwtRaw string, jwks jose.JSONWebKeySet) (json.RawMessage, error) {
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
