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
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/subject"
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
			if typ != AuthenticatorGeneric {
				return false, nil, nil
			}

			auth, err := newGenericAuthenticator(id, conf)

			return true, auth, err
		})
}

type genericAuthenticator struct {
	id                   string
	e                    endpoint.Endpoint
	ads                  extractors.AuthDataExtractStrategy
	payload              template.Template
	fwdHeaders           []string
	fwdCookies           []string
	sf                   PrincipalFactory
	ttl                  time.Duration
	sessionLifespanConf  *SessionLifespanConfig
	allowFallbackOnError bool
}

func newGenericAuthenticator(id string, rawConfig map[string]any) (*genericAuthenticator, error) {
	type Config struct {
		Endpoint              endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"     validate:"required"` //nolint:lll
		SubjectInfo           PrincipalInfo                       `mapstructure:"subject"                    validate:"required"` //nolint:lll
		AuthDataSource        extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source" validate:"required"` //nolint:lll
		ForwardHeaders        []string                            `mapstructure:"forward_headers"`
		ForwardCookies        []string                            `mapstructure:"forward_cookies"`
		Payload               template.Template                   `mapstructure:"payload"`
		SessionLifespanConfig *SessionLifespanConfig              `mapstructure:"session_lifespan"`
		CacheTTL              *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError  bool                                `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorGeneric, rawConfig, &conf); err != nil {
		return nil, err
	}

	return &genericAuthenticator{
		id:         id,
		e:          conf.Endpoint,
		ads:        conf.AuthDataSource,
		payload:    conf.Payload,
		fwdHeaders: conf.ForwardHeaders,
		fwdCookies: conf.ForwardCookies,
		sf:         &conf.SubjectInfo,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return 0 }),
		allowFallbackOnError: conf.AllowFallbackOnError,
		sessionLifespanConf:  conf.SessionLifespanConfig,
	}, nil
}

func (a *genericAuthenticator) Execute(ctx heimdall.Context, sub subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authenticating using generic authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to get authentication data from request").
			WithErrorContext(a).
			CausedBy(err)
	}

	payload, err := a.getSubjectInformation(ctx, authData)
	if err != nil {
		return err
	}

	principal, err := a.sf.CreatePrincipal(payload)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			WithErrorContext(a).
			CausedBy(err)
	}

	sub.AddPrincipal(a.id, principal)

	return nil
}

func (a *genericAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows ttl to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type Config struct {
		CacheTTL             *time.Duration `mapstructure:"cache_ttl"`
		AllowFallbackOnError *bool          `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(AuthenticatorGeneric, config, &conf); err != nil {
		return nil, err
	}

	return &genericAuthenticator{
		id:         a.id,
		e:          a.e,
		sf:         a.sf,
		ads:        a.ads,
		payload:    a.payload,
		fwdHeaders: a.fwdHeaders,
		fwdCookies: a.fwdCookies,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return a.ttl }),
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
		sessionLifespanConf: a.sessionLifespanConf,
	}, nil
}

func (a *genericAuthenticator) ContinueOnError() bool {
	return a.allowFallbackOnError
}

func (a *genericAuthenticator) ID() string {
	return a.id
}

func (a *genericAuthenticator) getSubjectInformation(ctx heimdall.Context, authData string) ([]byte, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey string
		session  *SessionLifespan
	)

	if a.ttl > 0 {
		cacheKey = a.calculateCacheKey(authData)
		if entry, err := cch.Get(ctx.AppContext(), cacheKey); err == nil {
			logger.Debug().Msg("Reusing subject information from cache")

			return entry, nil
		}
	}

	payload, err := a.fetchSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	if a.sessionLifespanConf != nil {
		session, err = a.sessionLifespanConf.CreateSessionLifespan(payload)
		if err != nil {
			return nil, errorchain.New(heimdall.ErrInternal).WithErrorContext(a).CausedBy(err)
		}

		if session != nil {
			if err = session.Assert(); err != nil {
				return nil, errorchain.New(heimdall.ErrAuthentication).WithErrorContext(a).CausedBy(err)
			}
		}
	}

	if cacheTTL := a.getCacheTTL(session); cacheTTL > 0 {
		if err = cch.Set(ctx.AppContext(), cacheKey, payload, cacheTTL); err != nil {
			logger.Warn().Err(err).Msg("Failed to cache subject information")
		}
	}

	return payload, nil
}

func (a *genericAuthenticator) fetchSubjectInformation(ctx heimdall.Context, authData string) ([]byte, error) {
	req, err := a.createRequest(ctx, authData)
	if err != nil {
		return nil, err
	}

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout,
					"request to the endpoint to get information about the user timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication,
				"request to the endpoint to get information about the user failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readResponse(resp)
}

func (a *genericAuthenticator) createRequest(ctx heimdall.Context, authData string) (*http.Request, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	var body io.Reader

	templateData := map[string]any{
		"AuthenticationData": authData,
	}

	if a.payload != nil {
		value, err := a.payload.Render(templateData)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to render payload for the authenticator endpoint").
				WithErrorContext(a).CausedBy(err)
		}

		body = strings.NewReader(value)
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), body,
		endpoint.RenderFunc(func(value string) (string, error) {
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

	for _, headerName := range a.fwdHeaders {
		headerValue := ctx.Request().Header(headerName)
		if len(headerValue) == 0 {
			logger.Warn().Str("_header", headerName).
				Msg("Header not present in the request but configured to be forwarded")
		} else {
			req.Header.Add(headerName, headerValue)
		}
	}

	for _, cookieName := range a.fwdCookies {
		cookieValue := ctx.Request().Cookie(cookieName)
		if len(cookieValue) == 0 {
			logger.Warn().Str("_cookie", cookieName).
				Msg("Cookie not present in the request but configured to be forwarded")
		} else {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
		}
	}

	return req, nil
}

func (a *genericAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode).WithErrorContext(a)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	return rawData, nil
}

func (a *genericAuthenticator) getCacheTTL(sessionLifespan *SessionLifespan) time.Duration {
	// timeLeeway defines the default time deviation to ensure the session is still valid
	// when used from cache
	const timeLeeway = 10

	if a.ttl <= 0 {
		return 0
	}

	// we cache using the settings in the configured ttl.
	// It is however ensured, that this ttl does not exceed the ttl of the session itself
	// (if this information is available)
	if sessionLifespan != nil && !sessionLifespan.exp.Equal(time.Time{}) {
		expiresIn := sessionLifespan.exp.Unix() - time.Now().Unix() - timeLeeway
		expirationTTL := x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)

		return min(a.ttl, expirationTTL)
	}

	return a.ttl
}

func (a *genericAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write(a.e.Hash())
	digest.Write(stringx.ToBytes(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
