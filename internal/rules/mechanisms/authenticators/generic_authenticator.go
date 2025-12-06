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

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthenticator,
		AuthenticatorGeneric,
		registry.FactoryFunc(newGenericAuthenticator),
	)
}

type genericAuthenticator struct {
	name                string
	id                  string
	principalName       string
	app                 app.Context
	e                   endpoint.Endpoint
	ads                 extractors.AuthDataExtractStrategy
	payload             template.Template
	fwdHeaders          []string
	fwdCookies          []string
	sf                  PrincipalFactory
	ttl                 time.Duration
	sessionLifespanConf *SessionLifespanConfig
}

func newGenericAuthenticator(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorGeneric).
		Str("_name", name).
		Msg("Creating authenticator")

	type Config struct {
		Endpoint              endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"     validate:"required"` //nolint:lll
		PrincipalInfo         PrincipalInfo                       `mapstructure:"principal"                  validate:"required"` //nolint:lll
		AuthDataSource        extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source" validate:"required"` //nolint:lll
		ForwardHeaders        []string                            `mapstructure:"forward_headers"`
		ForwardCookies        []string                            `mapstructure:"forward_cookies"`
		Payload               template.Template                   `mapstructure:"payload"`
		SessionLifespanConfig *SessionLifespanConfig              `mapstructure:"session_lifespan"`
		CacheTTL              *time.Duration                      `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorGeneric, name).CausedBy(err)
	}

	if strings.HasPrefix(conf.Endpoint.URL, "http://") {
		logger.Warn().
			Str("_type", AuthenticatorGeneric).
			Str("_name", name).
			Msg("No TLS configured for the endpoint used in authenticator")
	}

	return &genericAuthenticator{
		name:          name,
		id:            name,
		principalName: DefaultPrincipalName,
		app:           app,
		e:             conf.Endpoint,
		ads:           conf.AuthDataSource,
		payload:       conf.Payload,
		fwdHeaders:    conf.ForwardHeaders,
		fwdCookies:    conf.ForwardCookies,
		sf:            &conf.PrincipalInfo,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return 0 }),
		sessionLifespanConf: conf.SessionLifespanConfig,
	}, nil
}

func (a *genericAuthenticator) Accept(visitor heimdall.Visitor) {
	visitor.VisitInsecure(a)
	visitor.VisitPrincipalNamer(a)
}

func (a *genericAuthenticator) Execute(ctx heimdall.Context, sub identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthenticatorGeneric).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to get authentication data from request").
			WithErrorContext(a).
			CausedBy(err)
	}

	payload, err := a.getPrincipalInformation(ctx, authData)
	if err != nil {
		return err
	}

	principal, err := a.sf.CreatePrincipal(payload)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract principal information from response").
			WithErrorContext(a).
			CausedBy(err)
	}

	sub[a.principalName] = principal

	return nil
}

func (a *genericAuthenticator) CreateStep(def types.StepDefinition) (heimdall.Step, error) {
	// this authenticator allows ttl to be redefined on the rule level
	if def.IsEmpty() {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = x.IfThenElse(len(def.ID) == 0, a.id, def.ID)
		auth.principalName = x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal)

		return &auth, nil
	}

	// fields marked with "not_allowed" are not allowed to be configured
	type Config struct {
		Endpoint              *endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"     validate:"not_allowed"` //nolint:lll
		SubjectInfo           *PrincipalInfo                       `mapstructure:"principal"                  validate:"not_allowed"` //nolint:lll
		AuthDataSource        *extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source" validate:"not_allowed"` //nolint:lll
		ForwardHeaders        []string                             `mapstructure:"forward_headers"            validate:"not_allowed"` //nolint:lll
		ForwardCookies        []string                             `mapstructure:"forward_cookies"            validate:"not_allowed"` //nolint:lll
		Payload               *template.Template                   `mapstructure:"payload"                    validate:"not_allowed"` //nolint:lll
		SessionLifespanConfig *SessionLifespanConfig               `mapstructure:"session_lifespan"           validate:"not_allowed"` //nolint:lll
		CacheTTL              *time.Duration                       `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(a.app, def.Config, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorGeneric, a.name).CausedBy(err)
	}

	return &genericAuthenticator{
		name:          a.name,
		id:            x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		principalName: x.IfThenElse(len(def.Principal) == 0, a.principalName, def.Principal),
		app:           a.app,
		e:             a.e,
		sf:            a.sf,
		ads:           a.ads,
		payload:       a.payload,
		fwdHeaders:    a.fwdHeaders,
		fwdCookies:    a.fwdCookies,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return a.ttl }),
		sessionLifespanConf: a.sessionLifespanConf,
	}, nil
}

func (a *genericAuthenticator) Kind() types.Kind { return types.KindAuthenticator }

func (a *genericAuthenticator) Name() string { return a.name }

func (a *genericAuthenticator) ID() string { return a.id }

func (a *genericAuthenticator) IsInsecure() bool { return false }

func (a *genericAuthenticator) PrincipalName() string { return a.principalName }

func (a *genericAuthenticator) getPrincipalInformation(ctx heimdall.Context, authData string) ([]byte, error) {
	logger := zerolog.Ctx(ctx.Context())
	cch := cache.Ctx(ctx.Context())

	var (
		cacheKey string
		session  *SessionLifespan
	)

	if a.ttl > 0 {
		cacheKey = a.calculateCacheKey(authData)
		if entry, err := cch.Get(ctx.Context(), cacheKey); err == nil {
			logger.Debug().Msg("Reusing principal information from cache")

			return entry, nil
		}
	}

	payload, err := a.fetchPrincipalInformation(ctx, authData)
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
		if err = cch.Set(ctx.Context(), cacheKey, payload, cacheTTL); err != nil {
			logger.Warn().Err(err).Msg("Failed to cache principal information")
		}
	}

	return payload, nil
}

func (a *genericAuthenticator) fetchPrincipalInformation(ctx heimdall.Context, authData string) ([]byte, error) {
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
	logger := zerolog.Ctx(ctx.Context())

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

	req, err := a.e.CreateRequest(ctx.Context(), body,
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
			logger.Warn().
				Str("_header", headerName).
				Msg("Header not present in the request but configured to be forwarded")
		} else {
			req.Header.Add(headerName, headerValue)
		}
	}

	for _, cookieName := range a.fwdCookies {
		cookieValue := ctx.Request().Cookie(cookieName)
		if len(cookieValue) == 0 {
			logger.Warn().
				Str("_cookie", cookieName).
				Msg("Cookie not present in the request but configured to be forwarded")
		} else {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
		}
	}

	return req, nil
}

func (a *genericAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, errorchain.NewWithMessage(heimdall.ErrAuthentication,
			"received authentication data rejected").WithErrorContext(a)
	case resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices:
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
