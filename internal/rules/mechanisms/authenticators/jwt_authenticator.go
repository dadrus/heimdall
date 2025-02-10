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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
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
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorJwt {
				return false, nil, nil
			}

			auth, err := newJwtAuthenticator(app, id, conf)

			return true, auth, err
		})
}

type jwtAuthenticator struct {
	id                   string
	app                  app.Context
	r                    oauth2.ServerMetadataResolver
	a                    oauth2.Expectation
	ttl                  *time.Duration
	sf                   SubjectFactory
	ads                  extractors.AuthDataExtractStrategy
	allowFallbackOnError bool
	trustStore           truststore.TrustStore
	validateJWKCert      bool
}

// nolint: funlen, cyclop
func newJwtAuthenticator(
	app app.Context,
	id string,
	rawConfig map[string]any,
) (*jwtAuthenticator, error) { // nolint: funlen
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating jwt authenticator")

	type Config struct {
		JWKSEndpoint         *endpoint.Endpoint                  `mapstructure:"jwks_endpoint"        validate:"required_without=MetadataEndpoint,excluded_with=MetadataEndpoint"` //nolint:lll,tagalign
		MetadataEndpoint     *oauth2.MetadataEndpoint            `mapstructure:"metadata_endpoint"    validate:"required_without=JWKSEndpoint,excluded_with=JWKSEndpoint"`         //nolint:lll,tagalign
		Assertions           oauth2.Expectation                  `mapstructure:"assertions"           validate:"required_with=JWKSEndpoint"`                                       //nolint:lll,tagalign
		SubjectInfo          SubjectInfo                         `mapstructure:"subject"              validate:"-"`                                                                //nolint:lll,tagalign
		AuthDataSource       extractors.CompositeExtractStrategy `mapstructure:"jwt_source"`
		CacheTTL             *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError bool                                `mapstructure:"allow_fallback_on_error"`
		ValidateJWK          *bool                               `mapstructure:"validate_jwk"`
		TrustStore           truststore.TrustStore               `mapstructure:"trust_store"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for jwt authenticator '%s'", id).CausedBy(err)
	}

	if conf.JWKSEndpoint != nil {
		if len(conf.Assertions.TrustedIssuers) == 0 {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrConfiguration, "'issuers' is a required field if JWKS endpoint is used")
		}

		if strings.HasPrefix(conf.JWKSEndpoint.URL, "http://") {
			logger.Warn().Str("_id", id).
				Msg("No TLS configured for the jwks endpoint used in jwt authenticator. " +
					"NEVER DO THIS IN PRODUCTION!!!")
		}
	}

	if conf.MetadataEndpoint != nil && strings.HasPrefix(conf.MetadataEndpoint.URL, "http://") {
		logger.Warn().Str("_id", id).
			Msg("No TLS configured for the metadata endpoint used in jwt authenticator. " +
				"NEVER DO THIS IN PRODUCTION!!!")
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

	resolver := x.IfThenElseExec(conf.MetadataEndpoint != nil,
		func() oauth2.ServerMetadataResolver { return conf.MetadataEndpoint },
		func() oauth2.ServerMetadataResolver {
			ep := conf.JWKSEndpoint

			if ep.Headers == nil {
				ep.Headers = make(map[string]string)
			}

			if _, ok := ep.Headers["Accept"]; !ok {
				ep.Headers["Accept"] = "application/json"
			}

			if len(ep.Method) == 0 {
				ep.Method = http.MethodGet
			}

			return oauth2.ResolverAdapterFunc(
				func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
					return oauth2.ServerMetadata{JWKSEndpoint: ep}, nil
				},
			)
		},
	)

	return &jwtAuthenticator{
		id:                   id,
		app:                  app,
		r:                    resolver,
		a:                    conf.Assertions,
		ttl:                  conf.CacheTTL,
		sf:                   &conf.SubjectInfo,
		ads:                  ads,
		allowFallbackOnError: conf.AllowFallbackOnError,
		validateJWKCert:      validateJWKCert,
		trustStore:           conf.TrustStore,
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

	token, err := jwt.ParseSigned(jwtAd, supportedAlgorithms())
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
		Assertions           oauth2.Expectation `mapstructure:"assertions"              validate:"-"`
		CacheTTL             *time.Duration     `mapstructure:"cache_ttl"`
		AllowFallbackOnError *bool              `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(a.app, config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for jwt authenticator '%s'", a.id).CausedBy(err)
	}

	return &jwtAuthenticator{
		id:  a.id,
		app: a.app,
		r:   a.r,
		a:   conf.Assertions.Merge(a.a),
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

func (a *jwtAuthenticator) IsInsecure() bool { return false }

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

func (a *jwtAuthenticator) serverMetadata(ctx heimdall.Context, claims map[string]any) (oauth2.ServerMetadata, error) {
	metadata, err := a.r.Get(ctx.AppContext(), map[string]any{"TokenIssuer": claims["iss"]})
	if err != nil {
		return oauth2.ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed retrieving oauth2 server metadata").CausedBy(err).WithErrorContext(a)
	}

	if metadata.JWKSEndpoint == nil {
		return oauth2.ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"received server metadata does not contain the required jwks_uri").
			WithErrorContext(a)
	}

	return metadata, nil
}

func (a *jwtAuthenticator) verifyToken(ctx heimdall.Context, token *jwt.JSONWebToken) (json.RawMessage, error) {
	claims := map[string]any{}
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to deserialize JWT").
			WithErrorContext(a).
			CausedBy(err)
	}

	metadata, err := a.serverMetadata(ctx, claims)
	if err != nil {
		return nil, err
	}

	// configured assertions take precedence over those available in the metadata
	assertions := a.a.Merge(oauth2.Expectation{
		TrustedIssuers: []string{metadata.Issuer},
	})

	if len(token.Headers[0].KeyID) == 0 {
		return a.verifyTokenWithoutKID(ctx, token, claims, metadata.JWKSEndpoint, &assertions)
	}

	sigKey, err := a.getKey(ctx, token.Headers[0].KeyID, claims, metadata.JWKSEndpoint)
	if err != nil {
		return nil, err
	}

	return a.verifyTokenWithKey(token, sigKey, &assertions)
}

func (a *jwtAuthenticator) verifyTokenWithoutKID(
	ctx heimdall.Context,
	token *jwt.JSONWebToken,
	tokenClaims map[string]any,
	ep *endpoint.Endpoint,
	assertions *oauth2.Expectation,
) (json.RawMessage, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Info().Msg("No kid present in the JWT")

	var rawClaims json.RawMessage

	req, err := a.createRequest(ctx.AppContext(), ep, tokenClaims)
	if err != nil {
		return nil, err
	}

	jwks, err := a.fetchJWKS(ctx.AppContext(), ep.CreateClient(req.URL.Hostname()), req)
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

func (a *jwtAuthenticator) getKey(
	ctx heimdall.Context, keyID string, tokenClaims map[string]any, ep *endpoint.Endpoint,
) (*jose.JSONWebKey, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())

	var (
		cacheKey string
		jwks     *jose.JSONWebKeySet
	)

	req, err := a.createRequest(ctx.AppContext(), ep, tokenClaims)
	if err != nil {
		return nil, err
	}

	if a.isCacheEnabled() {
		cacheKey = a.calculateCacheKey(ep, req.URL.String(), keyID)
		if entry, err := cch.Get(ctx.AppContext(), cacheKey); err == nil {
			var jwk jose.JSONWebKey

			if err = json.Unmarshal(entry, &jwk); err == nil {
				logger.Debug().Msg("Reusing JWK from cache")

				return &jwk, nil
			}
		}
	}

	jwks, err = a.fetchJWKS(ctx.AppContext(), ep.CreateClient(req.URL.Hostname()), req)
	if err != nil {
		return nil, err
	}

	keys := jwks.Key(keyID)
	if len(keys) != 1 {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication,
				"no (unique) key found for the keyID='%s' referenced in the JWT", keyID).
			WithErrorContext(a)
	}

	jwk := &keys[0]
	if err = a.validateJWK(jwk); err != nil {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthentication, "JWK for keyID=%s is invalid", keyID).
			WithErrorContext(a).
			CausedBy(err)
	}

	if cacheTTL := a.getCacheTTL(jwk); cacheTTL > 0 {
		data, _ := json.Marshal(jwk)

		if err = cch.Set(ctx.AppContext(), cacheKey, data, cacheTTL); err != nil {
			logger.Warn().Err(err).Msg("Failed to cache JWK")
		}
	}

	return jwk, nil
}

func (a *jwtAuthenticator) fetchJWKS(
	ctx context.Context, client *http.Client, req *http.Request,
) (*jose.JSONWebKeySet, error) {
	logger := zerolog.Ctx(ctx)

	logger.Debug().Msg("Retrieving JWKS from configured endpoint")

	resp, err := client.Do(req)
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

	return a.readJWKS(resp)
}

func (a *jwtAuthenticator) createRequest(
	ctx context.Context, ep *endpoint.Endpoint, claims map[string]any,
) (*http.Request, error) {
	req, err := ep.CreateRequest(ctx, nil, endpoint.RenderFunc(func(value string) (string, error) {
		// ignoring closing braces here as it would anyway result in a broken template leading to an error
		if !strings.Contains(value, "{{") {
			return value, nil
		}

		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				CausedBy(err)
		}

		return tpl.Render(map[string]any{"TokenIssuer": claims["iss"]})
	}))
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(a).
			CausedBy(err)
	}

	return req, nil
}

func (a *jwtAuthenticator) readJWKS(resp *http.Response) (*jose.JSONWebKeySet, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode).
			WithErrorContext(a)
	}

	// unmarshal the received key set
	var jwks jose.JSONWebKeySet

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received jwks").
			WithErrorContext(a).
			CausedBy(err)
	}

	return &jwks, nil
}

func (a *jwtAuthenticator) verifyTokenWithKey(
	token *jwt.JSONWebToken, key *jose.JSONWebKey, assertions *oauth2.Expectation,
) (json.RawMessage, error) {
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

func (a *jwtAuthenticator) calculateCacheKey(ep *endpoint.Endpoint, renderedURL, reference string) string {
	digest := sha256.New()
	digest.Write(ep.Hash())
	digest.Write(stringx.ToBytes(renderedURL))
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
