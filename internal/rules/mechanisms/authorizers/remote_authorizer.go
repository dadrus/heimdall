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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/cellib"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authorizer, error) {
			if typ != AuthorizerRemote {
				return false, nil, nil
			}

			auth, err := newRemoteAuthorizer(id, conf)

			return true, auth, err
		})
}

type remoteAuthorizer struct {
	id                 string
	e                  endpoint.Endpoint
	payload            template.Template
	expressions        []*cellib.Expression
	headersForUpstream []string
	ttl                time.Duration
	celEnv             *cel.Env
}

type authorizationInformation struct {
	headers http.Header
	payload any
}

func (ai *authorizationInformation) addHeadersTo(headerNames []string, ctx heimdall.Context) {
	for _, headerName := range headerNames {
		headerValue := ai.headers.Get(headerName)
		if len(headerValue) != 0 {
			ctx.AddHeaderForUpstream(headerName, headerValue)
		}
	}
}

func (ai *authorizationInformation) addAttributesTo(key string, sub *subject.Subject) {
	if ai.payload != nil {
		sub.Attributes[key] = ai.payload
	}
}

func newRemoteAuthorizer(id string, rawConfig map[string]any) (*remoteAuthorizer, error) {
	type Config struct {
		Endpoint                 endpoint.Endpoint    `mapstructure:"endpoint"`
		Payload                  template.Template    `mapstructure:"payload"`
		Expressions              []*cellib.Expression `mapstructure:"expressions"`
		ResponseHeadersToForward []string             `mapstructure:"forward_response_headers_to_upstream"`
		CacheTTL                 time.Duration        `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal remote authorizer config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if len(conf.Endpoint.Headers) == 0 && conf.Payload == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"either a payload or at least one endpoint header must be configured for remote authorizer")
	}

	env, err := cel.NewEnv(cellib.Library())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating CEL environment").CausedBy(err)
	}

	for i, expression := range conf.Expressions {
		err = expression.Compile(env)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile expression %d (%s)", i+1, expression.Value).CausedBy(err)
		}
	}

	return &remoteAuthorizer{
		e:                  conf.Endpoint,
		id:                 id,
		payload:            conf.Payload,
		expressions:        conf.Expressions,
		headersForUpstream: conf.ResponseHeadersToForward,
		ttl:                conf.CacheTTL,
		celEnv:             env,
	}, nil
}

func (a *remoteAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", a.id).Msg("Authorizing using remote authorizer")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute remote authorizer due to 'nil' subject").
			WithErrorContext(a)
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey   string
		cacheEntry any
		authInfo   *authorizationInformation
		err        error
		ok         bool
	)

	if a.ttl > 0 {
		cacheKey = a.calculateCacheKey(sub)
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if authInfo, ok = cacheEntry.(*authorizationInformation); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing authorization information from cache")
		}
	}

	if authInfo == nil {
		authInfo, err = a.doAuthorize(ctx, sub)
		if err != nil {
			return err
		}

		if a.ttl > 0 && len(cacheKey) != 0 {
			cch.Set(cacheKey, authInfo, a.ttl)
		}
	}

	authInfo.addHeadersTo(a.headersForUpstream, ctx)
	authInfo.addAttributesTo(a.id, sub)

	return nil
}

func (a *remoteAuthorizer) WithConfig(rawConfig map[string]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	type Config struct {
		Payload                  template.Template    `mapstructure:"payload"`
		Expressions              []*cellib.Expression `mapstructure:"expressions"`
		ResponseHeadersToForward []string             `mapstructure:"forward_response_headers_to_upstream"`
		CacheTTL                 time.Duration        `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal remote authorizer config").
			CausedBy(err)
	}

	for i, expression := range conf.Expressions {
		err := expression.Compile(a.celEnv)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile expression %d (%s)", i+1, expression.Value).CausedBy(err)
		}
	}

	return &remoteAuthorizer{
		id:          a.id,
		e:           a.e,
		payload:     x.IfThenElse(conf.Payload != nil, conf.Payload, a.payload),
		celEnv:      a.celEnv,
		expressions: x.IfThenElse(len(conf.Expressions) != 0, conf.Expressions, a.expressions),
		headersForUpstream: x.IfThenElse(len(conf.ResponseHeadersToForward) != 0,
			conf.ResponseHeadersToForward, a.headersForUpstream),
		ttl: x.IfThenElse(conf.CacheTTL > 0, conf.CacheTTL, a.ttl),
	}, nil
}

func (a *remoteAuthorizer) HandlerID() string { return a.id }

func (a *remoteAuthorizer) ContinueOnError() bool { return false }

func (a *remoteAuthorizer) doAuthorize(ctx heimdall.Context, sub *subject.Subject) (*authorizationInformation, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Calling remote authorization endpoint")

	req, err := a.createRequest(ctx, sub)
	if err != nil {
		return nil, err
	}

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout,
					"request to the authorization endpoint timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to the authorization endpoint failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	data, err := a.readResponse(ctx, resp)
	if err != nil {
		return nil, err
	}

	err = a.verify(ctx, data)
	if err != nil {
		return nil, err
	}

	return &authorizationInformation{headers: resp.Header, payload: data}, nil
}

func (a *remoteAuthorizer) createRequest(ctx heimdall.Context, sub *subject.Subject) (*http.Request, error) {
	var body io.Reader

	if a.payload != nil {
		bodyContents, err := a.payload.Render(ctx, sub)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render payload for the authorization endpoint").
				WithErrorContext(a).
				CausedBy(err)
		}

		body = strings.NewReader(bodyContents)
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), body,
		endpoint.RenderFunc(func(value string) (string, error) {
			tpl, err := template.New(value)
			if err != nil {
				return "", errorchain.
					NewWithMessage(heimdall.ErrInternal, "failed to create template").
					WithErrorContext(a).
					CausedBy(err)
			}

			return tpl.Render(nil, sub)
		}))
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(a).
			CausedBy(err)
	}

	return req, nil
}

func (a *remoteAuthorizer) readResponse(ctx heimdall.Context, resp *http.Response) (any, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrAuthorization,
				"authorization failed based on received response code: %v", resp.StatusCode).
			WithErrorContext(a)
	}

	if resp.ContentLength == 0 {
		logger.Debug().Msg("No content received")

		return nil, nil
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	contentType := resp.Header.Get("Content-Type")

	decoder, err := contenttype.NewDecoder(contentType)
	if err != nil {
		logger.Warn().Str("_content_type", contentType).
			Msg("Content type is not supported. Treating it as string")

		return string(rawData), nil // nolint: nilerr
	}

	result, err := decoder.Decode(rawData)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			WithErrorContext(a).
			CausedBy(err)
	}

	return result, nil
}

func (a *remoteAuthorizer) calculateCacheKey(sub *subject.Subject) string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(a.ttl))

	hash := sha256.New()
	hash.Write(a.e.Hash())
	hash.Write([]byte(a.id))
	hash.Write([]byte(strings.Join(a.headersForUpstream, ",")))
	hash.Write(x.IfThenElseExec(a.payload != nil,
		func() []byte { return a.payload.Hash() },
		func() []byte { return []byte("nil") }))
	hash.Write(ttlBytes)
	hash.Write(sub.Hash())

	return hex.EncodeToString(hash.Sum(nil))
}

func (a *remoteAuthorizer) verify(ctx heimdall.Context, result any) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Verifying authorization response")

	obj := map[string]any{"Payload": result}

	for i, expression := range a.expressions {
		ok, err := expression.Eval(obj)
		if err != nil {
			return errorchain.NewWithMessagef(heimdall.ErrInternal, "failed evaluating expression %d", i+1).
				WithErrorContext(a).CausedBy(err)
		}

		if !ok {
			return errorchain.NewWithMessage(heimdall.ErrAuthorization,
				x.IfThenElse(len(expression.Message) != 0, expression.Message,
					fmt.Sprintf("expression %d failed", i+1))).
				WithErrorContext(a)
		}
	}

	return nil
}
