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
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/oauth2"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorOAuth2Introspection {
				return false, nil, nil
			}

			auth, err := newOAuth2IntrospectionAuthenticator(id, conf)

			return true, auth, err
		})
}

type oauth2IntrospectionAuthenticator struct {
	id                   string
	r                    oauth2.ServerMetadataResolver
	a                    oauth2.Expectation
	sf                   SubjectFactory
	ads                  extractors.AuthDataExtractStrategy
	ttl                  *time.Duration
	allowFallbackOnError bool
}

func newOAuth2IntrospectionAuthenticator(id string, rawConfig map[string]any) (
	*oauth2IntrospectionAuthenticator,
	error,
) {
	type Config struct {
		IntrospectionEndpoint *endpoint.Endpoint                  `mapstructure:"introspection_endpoint"  validate:"required_without=MetadataEndpoint,excluded_with=MetadataEndpoint"`           //nolint:lll,tagalign
		MetadataEndpoint      *endpoint.Endpoint                  `mapstructure:"metadata_endpoint"       validate:"required_without=IntrospectionEndpoint,excluded_with=IntrospectionEndpoint"` //nolint:lll
		Assertions            oauth2.Expectation                  `mapstructure:"assertions"              validate:"required"`
		SubjectInfo           SubjectInfo                         `mapstructure:"subject"                 validate:"-"`
		AuthDataSource        extractors.CompositeExtractStrategy `mapstructure:"token_source"`
		CacheTTL              *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError  bool                                `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorOAuth2Introspection, rawConfig, &conf); err != nil {
		return nil, err
	}

	if conf.IntrospectionEndpoint != nil && len(conf.Assertions.TrustedIssuers) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"'issuers' is a required field if introspection endpoint is used")
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
		func() oauth2.ServerMetadataResolver {
			return oauth2.NewServerMetadataResolver(conf.MetadataEndpoint)
		},
		func() oauth2.ServerMetadataResolver {
			ep := conf.IntrospectionEndpoint

			if ep.Headers == nil {
				ep.Headers = make(map[string]string)
			}

			if _, ok := ep.Headers["Content-Type"]; !ok {
				ep.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			}

			if _, ok := ep.Headers["Accept"]; !ok {
				ep.Headers["Accept"] = "application/json"
			}

			if len(ep.Method) == 0 {
				ep.Method = http.MethodPost
			}

			return oauth2.ResolverAdapterFunc(func(_ context.Context, _ map[string]any) (oauth2.ServerMetadata, error) {
				return oauth2.ServerMetadata{IntrospectionEndpoint: ep}, nil
			})
		},
	)

	return &oauth2IntrospectionAuthenticator{
		id:                   id,
		ads:                  ads,
		r:                    resolver,
		a:                    conf.Assertions,
		sf:                   &conf.SubjectInfo,
		ttl:                  conf.CacheTTL,
		allowFallbackOnError: conf.AllowFallbackOnError,
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using OAuth2 introspect authenticator")

	accessToken, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no access token present").
			WithErrorContext(a).
			CausedBy(err)
	}

	rawResp, err := a.getSubjectInformation(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	sub, err := a.sf.CreateSubject(rawResp)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal,
				"failed to extract subject information from introspection response").
			WithErrorContext(a).
			CausedBy(err)
	}

	return sub, nil
}

func (a *oauth2IntrospectionAuthenticator) WithConfig(rawConfig map[string]any) (Authenticator, error) {
	// this authenticator allows assertions and ttl to be redefined on the rule level
	if len(rawConfig) == 0 {
		return a, nil
	}

	type Config struct {
		Assertions           *oauth2.Expectation `mapstructure:"assertions"`
		CacheTTL             *time.Duration      `mapstructure:"cache_ttl"`
		AllowFallbackOnError *bool               `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorOAuth2Introspection, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &oauth2IntrospectionAuthenticator{
		id:  a.id,
		r:   a.r,
		a:   conf.Assertions.Merge(&a.a),
		sf:  a.sf,
		ads: a.ads,
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) IsFallbackOnErrorAllowed() bool {
	return a.allowFallbackOnError
}

func (a *oauth2IntrospectionAuthenticator) ID() string {
	return a.id
}

func (a *oauth2IntrospectionAuthenticator) serverMetadata(ctx heimdall.Context, token string) (oauth2.ServerMetadata, error) {
	// Pass the token into the template.
	// parseJWT can be used in the template to access other claims from the token.
	metadata, err := a.r.Get(ctx.AppContext(), map[string]any{"Token": token})
	if err != nil {
		var cause *errorchain.ErrorChain
		errors.As(err, &cause)

		return oauth2.ServerMetadata{}, cause.WithErrorContext(a)
	}

	return metadata, nil
}

func (a *oauth2IntrospectionAuthenticator) getSubjectInformation(ctx heimdall.Context, token string) ([]byte, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())

	var (
		cacheKey       string
		cacheEntry     any
		cachedResponse []byte
		ok             bool
	)

	metadata, err := a.serverMetadata(ctx, token)
	if err != nil {
		return nil, err
	}

	if a.isCacheEnabled() {
		cacheKey = a.calculateCacheKey(metadata.IntrospectionEndpoint, token)
		cacheEntry = cch.Get(ctx.AppContext(), cacheKey)
	}

	if cacheEntry != nil {
		if cachedResponse, ok = cacheEntry.([]byte); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(ctx.AppContext(), cacheKey)
		} else {
			logger.Debug().Msg("Reusing introspection response from cache")

			return cachedResponse, nil
		}
	}

	introspectResp, rawResp, err := a.fetchTokenIntrospectionResponse(ctx, token, metadata.IntrospectionEndpoint)
	if err != nil {
		return nil, err
	}

	// configured assertions take precedence over those available in the metadata
	assertions := a.a.Merge(&oauth2.Expectation{
		TrustedIssuers: []string{metadata.Issuer},
	})

	if err = introspectResp.Validate(assertions); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			WithErrorContext(a).
			CausedBy(err)
	}

	if cacheTTL := a.getCacheTTL(introspectResp); cacheTTL > 0 {
		cch.Set(ctx.AppContext(), cacheKey, rawResp, cacheTTL)
	}

	return rawResp, nil
}

func (a *oauth2IntrospectionAuthenticator) fetchTokenIntrospectionResponse(
	ctx heimdall.Context, token string, ep *endpoint.Endpoint,
) (*oauth2.IntrospectionResponse, []byte, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Msg("Retrieving information about the access token from the introspection endpoint")

	req, err := ep.CreateRequest(ctx.AppContext(), strings.NewReader(
		url.Values{
			"token":           []string{token},
			"token_type_hint": []string{"access_token"},
		}.Encode()), nil)
	if err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(a).
			CausedBy(err)
	}

	resp, err := ep.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout,
					"request to the introspection endpoint timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to the introspection endpoint failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readIntrospectionResponse(resp)
}

func (a *oauth2IntrospectionAuthenticator) readIntrospectionResponse(
	resp *http.Response,
) (*oauth2.IntrospectionResponse, []byte, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode).
			WithErrorContext(a)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	var introspectionResponse oauth2.IntrospectionResponse
	if err = json.Unmarshal(rawData, &introspectionResponse); err != nil {
		return nil, nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received introspection response").
			WithErrorContext(a).
			CausedBy(err)
	}

	return &introspectionResponse, rawData, nil
}

func (a *oauth2IntrospectionAuthenticator) isCacheEnabled() bool {
	// cache is enabled if it is not configured (in that case the ttl value from the
	// introspection response if used), or if it is configured and the value > 0
	return a.ttl == nil || (a.ttl != nil && *a.ttl > 0)
}

func (a *oauth2IntrospectionAuthenticator) getCacheTTL(introspectResp *oauth2.IntrospectionResponse) time.Duration {
	// timeLeeway defines the default time deviation to ensure the token is still valid
	// when used from cache
	const timeLeeway = 10

	if !a.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the introspection response (if available)
	// or if ttl has been configured. Latter overwrites the settings in the introspection response
	// if it is shorter than the ttl in the introspection response
	introspectionResponseTTL := x.IfThenElseExec(introspectResp.Expiry != nil,
		func() time.Duration {
			expiresIn := introspectResp.Expiry.Time().Unix() - time.Now().Unix() - timeLeeway

			return x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)
		},
		func() time.Duration { return 0 })

	configuredTTL := x.IfThenElseExec(a.ttl != nil,
		func() time.Duration { return *a.ttl },
		func() time.Duration { return 0 })

	switch {
	case configuredTTL == 0 && introspectionResponseTTL == 0:
		return 0
	case configuredTTL == 0 && introspectionResponseTTL != 0:
		return introspectionResponseTTL
	case configuredTTL != 0 && introspectionResponseTTL == 0:
		return configuredTTL
	default:
		return min(configuredTTL, introspectionResponseTTL)
	}
}

func (a *oauth2IntrospectionAuthenticator) calculateCacheKey(ep *endpoint.Endpoint, reference string) string {
	digest := sha256.New()
	digest.Write(ep.Hash())
	digest.Write(stringx.ToBytes(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
