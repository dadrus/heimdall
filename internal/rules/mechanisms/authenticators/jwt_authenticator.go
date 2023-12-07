// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package authenticators

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/oidc"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/truststore"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const defaultJWTAuthenticatorTTL = 10 * time.Minute

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorJwt {
				return false, nil, nil
			}

			auth, err := newJwtAuthenticator(id, conf)

			return true, auth, err
		})
}

type jwtAuthenticator struct {
	id                   string
	e                    endpoint.Endpoint
	a                    oauth2.Expectation
	ttl                  *time.Duration
	sf                   SubjectFactory
	ads                  extractors.AuthDataExtractStrategy
	allowFallbackOnError bool
	endpointIsDiscovery  bool
	trustStore           truststore.TrustStore
	validateJWKCert      bool
}

func newJwtAuthenticator(id string, rawConfig map[string]any) (*jwtAuthenticator, error) { // nolint: funlen
	type Config struct {
		JWKSEndpoint         *endpoint.Endpoint                  `mapstructure:"jwks_endpoint"           validate:"required_without=DiscoveryEndpoint,excluded_with=DiscoveryEndpoint"`
		DiscoveryEndpoint    *endpoint.Endpoint                  `mapstructure:"oidc_discovery_endpoint" validate:"required_without=JWKSEndpoint,excluded_with=JWKSEndpoint"`
		Assertions           oauth2.Expectation                  `mapstructure:"assertions"              validate:"required"`
		SubjectInfo          SubjectInfo                         `mapstructure:"subject"                 validate:"-"`
		AuthDataSource       extractors.CompositeExtractStrategy `mapstructure:"jwt_source"`
		CacheTTL             *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError bool                                `mapstructure:"allow_fallback_on_error"`
		ValidateJWK          *bool                               `mapstructure:"validate_jwk"`
		TrustStore           truststore.TrustStore               `mapstructure:"trust_store"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorJwt, rawConfig, &conf); err != nil {
		return nil, err
	}

	// Pick the right endpoint to apply defaults to, JWKSEndpoint if set, otherwise the discovery endpoint
	endpoint := x.IfThenElse(conf.JWKSEndpoint != nil, conf.JWKSEndpoint, conf.DiscoveryEndpoint)

	if endpoint.Headers == nil {
		endpoint.Headers = make(map[string]string)
	}

	if _, ok := endpoint.Headers["Accept-Type"]; !ok {
		endpoint.Headers["Accept-Type"] = "application/json"
	}

	if len(endpoint.Method) == 0 {
		endpoint.Method = "GET"
	}

	if conf.JWKSEndpoint != nil && len(conf.Assertions.TrustedIssuers) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "'issuers' is a required field if JWKS endpoint is used")
	}

	if len(conf.Assertions.AllowedAlgorithms) == 0 {
		conf.Assertions.AllowedAlgorithms = defaultAllowedAlgorithms()
	}

	if conf.Assertions.ScopesMatcher == nil {
		conf.Assertions.ScopesMatcher = oauth2.NoopMatcher{}
	}

	if len(conf.SubjectInfo.IDFrom) == 0 {
		conf.SubjectInfo.IDFrom = "sub"
	}

	validateJWKCert := x.IfThenElseExec(conf.ValidateJWK != nil,
		func() bool { return *conf.ValidateJWK },
		func() bool { return true })

	ads := x.IfThenElseExec(conf.AuthDataSource == nil,
		func() extractors.CompositeExtractStrategy {
			return extractors.CompositeExtractStrategy{
				extractors.HeaderValueExtractStrategy{Name: "Authorization", Scheme: "Bearer"},
				extractors.QueryParameterExtractStrategy{Name: "access_token"},
				extractors.BodyParameterExtractStrategy{Name: "access_token"},
			}
		},
		func() extractors.CompositeExtractStrategy { return conf.AuthDataSource },
	)

	return &jwtAuthenticator{
		id:                   id,
		e:                    *endpoint,
		a:                    conf.Assertions,
		ttl:                  conf.CacheTTL,
		sf:                   &conf.SubjectInfo,
		ads:                  ads,
		allowFallbackOnError: conf.AllowFallbackOnError,
		validateJWKCert:      validateJWKCert,
		trustStore:           conf.TrustStore,
		endpointIsDiscovery:  conf.JWKSEndpoint == nil,
	}, nil
}

func (a *jwtAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using JWT authenticator")

	jwtAd, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no JWT present").
			WithErrorContext(a).
			CausedBy(err)
	}

	token, err := jwt.ParseSigned(jwtAd)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to parse JWT").
			WithErrorContext(a).
			CausedBy(heimdall.ErrArgument).
			CausedBy(err)
	}

	rawClaims, err := a.verifyToken(ctx, token)
	if err != nil {
		return nil, err
	}

	sub, err := a.sf.CreateSubject(rawClaims)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from jwt").
			WithErrorContext(a).
			CausedBy(err)
	}

	return sub, nil
}

func (a *jwtAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows assertions and ttl to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type Config struct {
		Assertions           *oauth2.Expectation `mapstructure:"assertions"              validate:"-"`
		CacheTTL             *time.Duration      `mapstructure:"cache_ttl"`
		AllowFallbackOnError *bool               `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorJwt, config, &conf); err != nil {
		return nil, err
	}

	return &jwtAuthenticator{
		id:  a.id,
		e:   a.e,
		a:   conf.Assertions.Merge(&a.a),
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
		sf:  a.sf,
		ads: a.ads,
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
		validateJWKCert: a.validateJWKCert,
		trustStore:      a.trustStore,
	}, nil
}

func (a *jwtAuthenticator) IsFallbackOnErrorAllowed() bool {
	return a.allowFallbackOnError
}

func (a *jwtAuthenticator) ID() string {
	return a.id
}

func (a *jwtAuthenticator) isCacheEnabled() bool {
	// cache is enabled if ttl is not configured (in that case the ttl value from either
	// the jwk cert (if available) or the defaultTTL is used), or if ttl is configured and
	// the value > 0
	return a.ttl == nil || (a.ttl != nil && *a.ttl > 0)
}

func (a *jwtAuthenticator) getCacheTTL(key *jose.JSONWebKey) time.Duration {
	// timeLeeway defines the default time deviation to ensure the cert of the JWK is still valid
	// when used from cache
	const timeLeeway = 10

	if !a.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the certificate (if available)
	// or based on ttl. Latter overwrites the settings in the certificate
	// if it is shorter than the ttl of the certificate
	certTTL := x.IfThenElseExec(len(key.Certificates) != 0,
		func() time.Duration {
			expiresIn := key.Certificates[0].NotAfter.Unix() - time.Now().Unix() - timeLeeway

			return x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)
		},
		func() time.Duration { return 0 })

	configuredTTL := x.IfThenElseExec(a.ttl != nil,
		func() time.Duration { return *a.ttl },
		func() time.Duration { return defaultJWTAuthenticatorTTL })

	switch {
	case configuredTTL == 0 && certTTL == 0:
		return 0
	case configuredTTL == 0 && certTTL != 0:
		return certTTL
	case configuredTTL != 0 && certTTL == 0:
		return configuredTTL
	default:
		return min(configuredTTL, certTTL)
	}
}

func (a *jwtAuthenticator) verifyToken(ctx heimdall.Context, token *jwt.JSONWebToken) (json.RawMessage, error) {
	if len(token.Headers[0].KeyID) == 0 {
		return a.verifyTokenWithoutKID(ctx, token)
	}

	sigKey, assertions, err := a.getKey(ctx, token.Headers[0].KeyID, token)
	if err != nil {
		return nil, err
	}

	return a.verifyTokenWithKey(token, sigKey, assertions)
}

func (a *jwtAuthenticator) verifyTokenWithoutKID(ctx heimdall.Context, token *jwt.JSONWebToken) (
	json.RawMessage, error,
) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Info().Msg("No kid present in the JWT")

	var rawClaims json.RawMessage

	ep, assertions, err := a.resolveOpenIdDiscovery(ctx, token)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to resolve OIDC discovery document").
			WithErrorContext(a).
			CausedBy(err)
	}

	jwks, err := a.fetchJWKS(ctx, ep)
	if err != nil {
		return nil, err
	}

	for idx := range jwks.Keys {
		sigKey := jwks.Keys[idx]
		if err = a.validateJWK(&sigKey); err != nil {
			logger.Info().Err(err).Str("_key_id", sigKey.KeyID).Msg("JWK is invalid")

			continue
		}

		rawClaims, err = a.verifyTokenWithKey(token, &sigKey, assertions)
		if err == nil {
			break
		}

		logger.Info().Err(err).Str("_key_id", sigKey.KeyID).Msg("Failed to verify JWT")
	}

	if len(rawClaims) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication,
				"None of the keys received from the JWKS endpoint could be used to verify the JWT").
			WithErrorContext(a)
	}

	return rawClaims, nil
}

func (a *jwtAuthenticator) resolveOpenIdDiscovery(ctx heimdall.Context, token *jwt.JSONWebToken) (*endpoint.Endpoint, *oauth2.Expectation, error) {
	// the authenticator is configured to not have discovery enabled, so reuse the values.
	if !a.endpointIsDiscovery {
		return &a.e, &a.a, nil
	}

	// a.e is the OIDC discovery URL here

	// Provide the "JWT" object to the render func template, so we can use it.
	tokenData := map[string]any{}
	if err := token.UnsafeClaimsWithoutVerification(&tokenData); err != nil {
		return nil, nil, errorchain.NewWithMessage(heimdall.ErrArgument, "failed to deserialize JWT").
			WithErrorContext(a).
			CausedBy(err)
	}

	templateData := map[string]any{
		"JWT": tokenData,
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), nil, endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				WithErrorContext(a).
				CausedBy(err)
		}

		return tpl.Render(templateData)
	}))

	if err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating openid discovery request").
			WithErrorContext(a).
			CausedBy(err)
	}

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to openid discovery endpoint timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to openid discovery endpoint failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode).
			WithErrorContext(a)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	// unmarshal the received discovery document
	var discovery oidc.DiscoveryDocument
	if err := json.Unmarshal(rawData, &discovery); err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received discovery document").
			WithErrorContext(a).
			CausedBy(err)
	}

	ep := &endpoint.Endpoint{
		URL:              discovery.JWKSUrl,
		Method:           "GET",
		Retry:            a.e.Retry,
		AuthStrategy:     a.e.AuthStrategy,
		HTTPCacheEnabled: a.e.HTTPCacheEnabled,
		Headers:          a.e.Headers,
	}

	// We do only need to check for the issuer here
	// While it would theoretically be possible to also check for the algorithms,
	// token validation will fail anyway because no key for an unsupported algorithm would be present
	// so it doesn't make sense to double check these.
	oidcIssuer := &oauth2.Expectation{
		TrustedIssuers: []string{discovery.Issuer},
	}
	assertions := oidcIssuer.Merge(&a.a)

	return ep, &assertions, nil
}

func (a *jwtAuthenticator) getKey(ctx heimdall.Context, keyID string, token *jwt.JSONWebToken) (*jose.JSONWebKey, *oauth2.Expectation, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())

	var (
		cacheKey   string
		cacheEntry any
		jwk        *jose.JSONWebKey
		jwks       *jose.JSONWebKeySet
		err        error
		ok         bool
	)

	ep, assertions, err := a.resolveOpenIdDiscovery(ctx, token)
	if err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to resolve OIDC discovery document").
			WithErrorContext(a).
			CausedBy(err)
	}

	if a.isCacheEnabled() {
		cacheKey = a.calculateCacheKey(keyID)
		cacheEntry = cch.Get(ctx.AppContext(), cacheKey)
	}

	if cacheEntry != nil {
		if jwk, ok = cacheEntry.(*jose.JSONWebKey); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(ctx.AppContext(), cacheKey)
		} else {
			logger.Debug().Msg("Reusing JWK from cache")
		}
	}

	if jwk != nil {
		return jwk, assertions, nil
	}

	jwks, err = a.fetchJWKS(ctx, ep)
	if err != nil {
		return nil, nil, err
	}

	keys := jwks.Key(keyID)
	if len(keys) != 1 {
		return nil, nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication,
				"no (unique) key found for the keyID='%s' referenced in the JWT", keyID).
			WithErrorContext(a)
	}

	jwk = &keys[0]
	if err = a.validateJWK(jwk); err != nil {
		return nil, nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "JWK for keyID=%s is invalid", keyID).
			WithErrorContext(a).
			CausedBy(err)
	}

	if cacheTTL := a.getCacheTTL(jwk); cacheTTL > 0 {
		cch.Set(ctx.AppContext(), cacheKey, jwk, cacheTTL)
	}

	return jwk, assertions, nil
}

func (a *jwtAuthenticator) fetchJWKS(ctx heimdall.Context, ep *endpoint.Endpoint) (*jose.JSONWebKeySet, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Msg("Retrieving JWKS from configured endpoint")

	templateData := map[string]any{}

	req, err := ep.CreateRequest(ctx.AppContext(), nil, endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				WithErrorContext(a).
				CausedBy(err)
		}

		return tpl.Render(templateData)
	}))

	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(a).
			CausedBy(err)
	}

	resp, err := ep.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to JWKS endpoint timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to JWKS endpoint failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()
	jwks, err := a.readJWKS(resp)

	return jwks, err
}

func (a *jwtAuthenticator) readJWKS(resp *http.Response) (*jose.JSONWebKeySet, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode).
			WithErrorContext(a)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	// unmarshal the received key set
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawData, &jwks); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received jwks").
			WithErrorContext(a).
			CausedBy(err)
	}

	return &jwks, nil
}

func (a *jwtAuthenticator) verifyTokenWithKey(token *jwt.JSONWebToken, key *jose.JSONWebKey, assertions *oauth2.Expectation) (json.RawMessage, error) {
	header := token.Headers[0]

	if len(header.Algorithm) != 0 && key.Algorithm != header.Algorithm {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication,
				"algorithm in the JWT header does not match the algorithm referenced in the key").
			WithErrorContext(a)
	}

	if err := assertions.AssertAlgorithm(key.Algorithm); err != nil {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "%s algorithm is not allowed", key.Algorithm).
			WithErrorContext(a).
			CausedBy(err)
	}

	var (
		mapClaims map[string]interface{}
		claims    oauth2.Claims
	)

	if err := token.Claims(key, &mapClaims, &claims); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to verify JWT signature").
			WithErrorContext(a).
			CausedBy(err)
	}

	if err := claims.Validate(*assertions); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			WithErrorContext(a).
			CausedBy(err)
	}

	rawPayload, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal jwt payload").
			WithErrorContext(a).
			CausedBy(err)
	}

	return rawPayload, nil
}

func (a *jwtAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write(a.e.Hash())
	digest.Write(stringx.ToBytes(reference))

	return hex.EncodeToString(digest.Sum(nil))
}

func (a *jwtAuthenticator) validateJWK(jwk *jose.JSONWebKey) error {
	if !a.validateJWKCert || len(jwk.Certificates) == 0 {
		return nil
	}

	return pkix.ValidateCertificate(jwk.Certificates[0],
		pkix.WithIntermediateCACertificates(jwk.Certificates[1:]),
		pkix.WithKeyUsage(x509.KeyUsageDigitalSignature),
		x.IfThenElseExec(len(a.trustStore) == 0,
			pkix.WithSystemTrustStore,
			func() pkix.ValidationOption { return pkix.WithRootCACertificates(a.trustStore) }),
	)
}
