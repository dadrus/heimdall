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

package authorizers

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/cachekey"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var errNoContent = errors.New("no payload received")

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registry.Register(
		types.KindAuthorizer,
		AuthorizerRemote,
		registry.FactoryFunc(newRemoteAuthorizer),
	)
}

type remoteAuthorizer struct {
	name        string
	id          string
	app         app.Context
	e           endpoint.Endpoint
	payload     template.Template
	expressions compiledExpressions
	ttl         time.Duration
	celEnv      *cel.Env
	v           values.Values
}

func newRemoteAuthorizer(app app.Context, name string, rawConfig map[string]any) (types.Mechanism, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthorizerRemote).
		Str("_name", name).
		Msg("Creating authorizer")

	type Config struct {
		Endpoint    endpoint.Endpoint `mapstructure:"endpoint"    validate:"required"` //nolint:lll
		Expressions []Expression      `mapstructure:"expressions" validate:"dive"`
		Payload     template.Template `mapstructure:"payload"     validate:"required_without=Endpoint.Headers"` //nolint:lll
		CacheTTL    time.Duration     `mapstructure:"cache_ttl"`
		Values      values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf,
		template.WithName("authorizer."+AuthorizerRemote+"."+name),
		template.WithSecretResolver(app.SecretResolver()),
	); err != nil {
		return nil, errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed decoding config for %s authorizer '%s'", AuthorizerRemote, name,
		).CausedBy(err)
	}

	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrInternal,
			"failed creating CEL environment",
		).CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, env)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(conf.Endpoint.URL.String(), "http://") {
		logger.Warn().
			Str("_type", AuthorizerRemote).
			Str("_name", name).
			Msg("No TLS configured for the endpoint used in authorizer")
	}

	return &remoteAuthorizer{
		name:        name,
		id:          name,
		app:         app,
		e:           conf.Endpoint,
		payload:     conf.Payload,
		expressions: expressions,
		ttl:         conf.CacheTTL,
		celEnv:      env,
		v:           conf.Values,
	}, nil
}

//nolint:cyclop
func (a *remoteAuthorizer) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().
		Str("_type", AuthorizerRemote).
		Str("_name", a.name).
		Str("_id", a.id).
		Msg("Executing authorizer")

	cch := cache.Ctx(ctx.Context())

	var (
		cacheKey string
		authInfo *pipeline.Result
		fetched  bool
	)

	vals, payload, err := a.renderTemplates(ctx, sub)
	if err != nil {
		return err
	}

	req, err := a.createRequest(ctx, sub, vals, payload)
	if err != nil {
		return err
	}

	if a.ttl > 0 {
		cacheKey = a.calculateCacheKey(req, payload)

		if entry, err := cch.Get(ctx.Context(), cacheKey); err == nil {
			var ai pipeline.Result

			if err = json.Unmarshal(entry, &ai); err == nil {
				logger.Debug().Msg("Reusing authorization information from cache")

				authInfo = &ai
			}
		}
	}

	if authInfo == nil {
		authInfo, err = a.fetchAuthorizationInformation(ctx, req)
		if err != nil {
			return err
		}

		fetched = true
	}

	if err = a.verify(ctx, authInfo.Payload); err != nil {
		return err
	}

	if fetched && len(cacheKey) != 0 {
		data, _ := json.Marshal(authInfo)

		if err = cch.Set(ctx.Context(), cacheKey, data, a.ttl); err != nil {
			logger.Warn().Err(err).Msg("Failed to cache authorization information")
		}
	}

	ctx.Results()[a.id] = authInfo

	return nil
}

func (a *remoteAuthorizer) CreateStep(
	resolver secrets.Resolver,
	def types.StepDefinition,
) (pipeline.Step, error) {
	if len(def.ID) == 0 && len(def.Config) == 0 {
		return a, nil
	}

	if len(def.Config) == 0 {
		auth := *a
		auth.id = def.ID

		return &auth, nil
	}

	type Config struct {
		Endpoint    *endpoint.Endpoint `mapstructure:"endpoint"    validate:"not_allowed"`
		Payload     template.Template  `mapstructure:"payload"`
		Expressions []Expression       `mapstructure:"expressions" validate:"dive"`
		CacheTTL    time.Duration      `mapstructure:"cache_ttl"`
		Values      values.Values      `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(a.app, def.Config, &conf,
		template.WithName("authorizer."+AuthorizerRemote+"."+a.name),
		template.WithSecretResolver(resolver),
	); err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed decoding config for remote authorizer '%s'", a.name).CausedBy(err)
	}

	expressions, err := compileExpressions(conf.Expressions, a.celEnv)
	if err != nil {
		return nil, err
	}

	return &remoteAuthorizer{
		name:        a.name,
		id:          x.IfThenElse(len(def.ID) == 0, a.id, def.ID),
		app:         a.app,
		e:           a.e,
		payload:     x.IfThenElse(conf.Payload != nil, conf.Payload, a.payload),
		celEnv:      a.celEnv,
		expressions: x.IfThenElse(len(expressions) != 0, expressions, a.expressions),
		ttl:         x.IfThenElse(conf.CacheTTL > 0, conf.CacheTTL, a.ttl),
		v:           a.v.Merge(conf.Values),
	}, nil
}

func (a *remoteAuthorizer) Name() string            { return a.name }
func (a *remoteAuthorizer) ID() string              { return a.id }
func (a *remoteAuthorizer) Type() string            { return a.name }
func (*remoteAuthorizer) Kind() types.Kind          { return types.KindAuthorizer }
func (*remoteAuthorizer) Accept(_ pipeline.Visitor) {}

func (a *remoteAuthorizer) createRequest(
	ctx pipeline.Context,
	sub pipeline.Subject,
	values map[string]string,
	payload string,
) (*http.Request, error) {
	req, err := a.e.CreateRequest(
		ctx.Context(),
		strings.NewReader(payload),
		map[string]any{
			"Subject": sub,
			"Values":  values,
			"Outputs": ctx.Results(),
			"Results": ctx.Results(),
		},
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrInternal, "failed creating request").
			WithAspects(a).
			CausedBy(err)
	}

	return req, nil
}

func (a *remoteAuthorizer) fetchAuthorizationInformation(
	ctx pipeline.Context,
	req *http.Request,
) (*pipeline.Result, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Msg("Calling remote authorization endpoint")

	client := a.e.CreateClient(req.URL.Hostname())
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(pipeline.ErrCommunicationTimeout,
				"request to the authorization endpoint timed out").
				WithAspects(a).
				CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(pipeline.ErrCommunication,
			"request to the authorization endpoint failed").
			WithAspects(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	data, err := a.readResponse(ctx, resp)
	if err != nil && !errors.Is(err, errNoContent) {
		return nil, err
	}

	return pipeline.NewResultWithHeaders(data, resp.Header), nil
}

func (a *remoteAuthorizer) readResponse(ctx pipeline.Context, resp *http.Response) (any, error) {
	logger := zerolog.Ctx(ctx.Context())

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, errorchain.NewWithMessagef(pipeline.ErrAuthorization,
			"authorization failed based on received response code: %v", resp.StatusCode).
			WithAspects(a)
	}

	if resp.ContentLength == 0 {
		logger.Debug().Msg("No content received")

		return nil, errNoContent
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrInternal, "failed to read response").
			WithAspects(a).
			CausedBy(err)
	}

	contentType := resp.Header.Get("Content-Type")

	decoder, err := contenttype.NewDecoder(contentType)
	if err != nil {
		logger.Warn().
			Str("_content_type", contentType).
			Msg("Content type is not supported. Treating it as string")

		return stringx.ToString(rawData), nil //nolint:nilerr
	}

	result, err := decoder.Decode(rawData)
	if err != nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrInternal, "failed to unmarshal response").
			WithAspects(a).
			CausedBy(err)
	}

	return result, nil
}

func (a *remoteAuthorizer) calculateCacheKey(req *http.Request, payload string) string {
	key := cachekey.New("remote-authorizer:response")

	key.WriteString(a.name)
	key.WriteInt64(int64(a.ttl))
	key.WriteString(req.Method)
	key.WriteString(req.URL.String())
	key.WriteHeader(req.Header)
	key.WriteString(payload)

	key.WriteBool(a.e.AuthStrategy != nil)

	if a.e.AuthStrategy != nil {
		key.WriteBytes(a.e.AuthStrategy.Hash())
	}

	return key.SumString()
}

func (a *remoteAuthorizer) verify(ctx pipeline.Context, result any) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Msg("Verifying authorization response")

	return a.expressions.eval(
		map[string]any{"Payload": result},
		a,
	)
}

func (a *remoteAuthorizer) renderTemplates(
	ctx pipeline.Context,
	sub pipeline.Subject,
) (map[string]string, string, error) {
	var payload string

	vals, err := a.v.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Results(),
		"Results": ctx.Results(),
	})
	if err != nil {
		return nil, "", errorchain.NewWithMessage(pipeline.ErrInternal,
			"failed to render values for the authorization endpoint").
			WithAspects(a).
			CausedBy(err)
	}

	if a.payload != nil {
		if payload, err = a.payload.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Values":  vals,
			"Outputs": ctx.Results(),
			"Results": ctx.Results(),
		}); err != nil {
			return nil, "", errorchain.NewWithMessage(pipeline.ErrInternal,
				"failed to render payload for the authorization endpoint").
				WithAspects(a).
				CausedBy(err)
		}
	}

	return vals, payload, nil
}
