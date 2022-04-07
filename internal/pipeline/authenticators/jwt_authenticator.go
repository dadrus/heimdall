package authenticators

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	RegisterAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTJwt {
				return false, nil, nil
			}

			auth, err := newJwtAuthenticator(conf)

			return true, auth, err
		})
}

type jwtAuthenticator struct {
	e   endpoint.Endpoint
	a   oauth2.Expectation
	ttl *time.Duration
	se  SubjectExtrator
	adg extractors.AuthDataExtractStrategy
}

func newJwtAuthenticator(rawConfig map[string]any) (*jwtAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint                   `mapstructure:"jwks_endpoint"`
		AuthDataSource extractors.CompositeExtractStrategy `mapstructure:"jwt_token_from"`
		JwtAssertions  oauth2.Expectation                  `mapstructure:"jwt_assertions"`
		Session        Session                             `mapstructure:"session"`
		CacheTTL       *time.Duration                      `mapstructure:"cache_ttl"`
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
		conf.JwtAssertions.AllowedAlgorithms = defaultAllowedAlgorithms()
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
			extractors.CookieValueExtractStrategy{Name: "access_token"},
			extractors.QueryParameterExtractStrategy{Name: "access_token"},
		}
	} else {
		adg = conf.AuthDataSource
	}

	return &jwtAuthenticator{
		e:   conf.Endpoint,
		a:   conf.JwtAssertions,
		ttl: conf.CacheTTL,
		se:  &conf.Session,
		adg: adg,
	}, nil
}

func (a *jwtAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using JWT authenticator")

	jwtAd, err := a.adg.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no JWT token present").CausedBy(err)
	}

	token, err := a.parseJWT(jwtAd.Value())
	if err != nil {
		return nil, err
	}

	sigKey, err := a.getKey(ctx, token.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}

	rawClaims, err := a.verifyTokenAndGetClaims(token, sigKey)
	if err != nil {
		return nil, err
	}

	sub, err := a.se.GetSubject(rawClaims)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from jwt").
			CausedBy(err)
	}

	return sub, nil
}

func (a *jwtAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows assertions and ttl to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		JwtAssertions oauth2.Expectation `mapstructure:"jwt_assertions"`
		CacheTTL      *time.Duration     `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	return &jwtAuthenticator{
		e:   a.e,
		a:   conf.JwtAssertions,
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
		se:  a.se,
		adg: a.adg,
	}, nil
}

func (a *jwtAuthenticator) parseJWT(rawJWT string) (*jwt.JSONWebToken, error) {
	const jwtDotCount = 2

	if strings.Count(rawJWT, ".") != jwtDotCount {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "unsupported JWT format")
	}

	token, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to parse JWT").CausedBy(err)
	}

	return token, nil
}

func (a *jwtAuthenticator) getKey(ctx heimdall.Context, keyID string) (*jose.JSONWebKey, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())
	cacheKey := a.getCacheKey(keyID)

	var cacheTTL time.Duration
	if a.ttl != nil {
		cacheTTL = *a.ttl
	}

	if cacheTTL != 0 {
		if item := cch.Get(cacheKey); item != nil {
			if cachedSigKey, ok := item.(*jose.JSONWebKey); !ok {
				logger.Warn().Msg("Wrong object type from cache")
				cch.Delete(cacheKey)
			} else {
				logger.Debug().Msg("Reusing signature key from cache")

				return cachedSigKey, nil
			}
		}
	}

	jwks, err := a.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	keys := jwks.Key(keyID)
	if len(keys) != 1 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication,
				"no (unique) key found for the keyID='%s' referenced in the JWT", keyID).
			CausedBy(err)
	}

	if cacheTTL != 0 {
		cch.Set(cacheKey, &keys[0], cacheTTL)
	}

	return &keys[0], nil
}

func (a *jwtAuthenticator) fetchJWKS(ctx heimdall.Context) (*jose.JSONWebKeySet, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Msg("Retrieving JWKS from configured endpoint")

	req, err := a.e.CreateRequest(ctx.AppContext(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.e.CreateClient().Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to jwks endpoint timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to jwks endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readJWKS(resp)
}

func (a *jwtAuthenticator) readJWKS(resp *http.Response) (*jose.JSONWebKeySet, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		// unmarshal the received key set
		var jwks jose.JSONWebKeySet
		if err := json.Unmarshal(rawData, &jwks); err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received jwks").
				CausedBy(err)
		}

		return &jwks, nil
	}

	return nil, errorchain.
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode)
}

func (a *jwtAuthenticator) verifyTokenAndGetClaims(
	token *jwt.JSONWebToken,
	key *jose.JSONWebKey,
) (json.RawMessage, error) {
	header := token.Headers[0]

	if len(header.Algorithm) != 0 && key.Algorithm != header.Algorithm {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication,
				"algorithm in the JWT header does not match the algorithm referenced in the key")
	}

	if !a.a.IsAlgorithmAllowed(key.Algorithm) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "%s algorithm is not allowed", key.Algorithm)
	}

	var (
		mapClaims map[string]interface{}
		claims    oauth2.Claims
	)

	if err := token.Claims(key, &mapClaims, &claims); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to verify JWT signature").
			CausedBy(err)
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

func (a *jwtAuthenticator) getCacheKey(reference string) string {
	return fmt.Sprintf("%s-%s", a.e.URL, reference)
}
