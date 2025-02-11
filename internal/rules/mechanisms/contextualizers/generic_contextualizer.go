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

package contextualizers

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	defaultTTL = 10 * time.Second
)

var errNoContent = errors.New("no payload received")

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Contextualizer, error) {
			if typ != ContextualizerGeneric {
				return false, nil, nil
			}

			eh, err := newGenericContextualizer(app, id, conf)

			return true, eh, err
		})
}

type contextualizerData struct {
	Payload any `json:"payload"`
}

type genericContextualizer struct {
	id              string
	app             app.Context
	e               endpoint.Endpoint
	ttl             time.Duration
	payload         template.Template
	fwdHeaders      []string
	fwdCookies      []string
	continueOnError bool
	v               values.Values
}

func newGenericContextualizer(
	app app.Context,
	id string,
	rawConfig map[string]any,
) (*genericContextualizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating generic contextualizer")

	type Config struct {
		Endpoint        endpoint.Endpoint `mapstructure:"endpoint"                   validate:"required"`
		ForwardHeaders  []string          `mapstructure:"forward_headers"`
		ForwardCookies  []string          `mapstructure:"forward_cookies"`
		Payload         template.Template `mapstructure:"payload"`
		CacheTTL        *time.Duration    `mapstructure:"cache_ttl"`
		ContinueOnError bool              `mapstructure:"continue_pipeline_on_error"`
		Values          values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for generic contextualizer '%s'", id).CausedBy(err)
	}

	if strings.HasPrefix(conf.Endpoint.URL, "http://") {
		logger.Warn().Str("_id", id).
			Msg("No TLS configured for the endpoint used in generic contextualizer")
	}

	ttl := defaultTTL
	if conf.CacheTTL != nil {
		ttl = *conf.CacheTTL
	}

	return &genericContextualizer{
		id:              id,
		app:             app,
		e:               conf.Endpoint,
		payload:         conf.Payload,
		fwdHeaders:      conf.ForwardHeaders,
		fwdCookies:      conf.ForwardCookies,
		ttl:             ttl,
		continueOnError: conf.ContinueOnError,
		v:               conf.Values,
	}, nil
}

//nolint:cyclop
func (c *genericContextualizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", c.id).Msg("Updating using generic contextualizer")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to execute generic contextualizer due to 'nil' subject").
			WithErrorContext(c)
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey string
		response *contextualizerData
	)

	vals, payload, err := c.renderTemplates(ctx, sub)
	if err != nil {
		return err
	}

	if c.ttl > 0 {
		cacheKey = c.calculateCacheKey(sub, vals, payload)
		if entry, err := cch.Get(ctx.AppContext(), cacheKey); err == nil {
			var cd contextualizerData

			if err = json.Unmarshal(entry, &cd); err == nil {
				logger.Debug().Msg("Reusing contextualizer response from cache")

				response = &cd
			}
		}
	}

	if response == nil {
		response, err = c.callEndpoint(ctx, sub, vals, payload)
		if err != nil {
			return err
		}

		if c.ttl > 0 && len(cacheKey) != 0 {
			data, _ := json.Marshal(response)

			if err = cch.Set(ctx.AppContext(), cacheKey, data, c.ttl); err != nil {
				logger.Warn().Err(err).Msg("Failed to cache contextualizer response")
			}
		}
	}

	if response.Payload != nil {
		ctx.Outputs()[c.id] = response.Payload
	}

	return nil
}

func (c *genericContextualizer) WithConfig(rawConfig map[string]any) (Contextualizer, error) {
	if len(rawConfig) == 0 {
		return c, nil
	}

	type Config struct {
		ForwardHeaders  []string          `mapstructure:"forward_headers"`
		ForwardCookies  []string          `mapstructure:"forward_cookies"`
		Payload         template.Template `mapstructure:"payload"`
		CacheTTL        *time.Duration    `mapstructure:"cache_ttl"`
		ContinueOnError *bool             `mapstructure:"continue_pipeline_on_error"`
		Values          values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(c.app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for generic contextualizer '%s'", c.id).CausedBy(err)
	}

	return &genericContextualizer{
		id:         c.id,
		app:        c.app,
		e:          c.e,
		payload:    x.IfThenElse(conf.Payload != nil, conf.Payload, c.payload),
		fwdHeaders: x.IfThenElse(len(conf.ForwardHeaders) != 0, conf.ForwardHeaders, c.fwdHeaders),
		fwdCookies: x.IfThenElse(len(conf.ForwardCookies) != 0, conf.ForwardCookies, c.fwdCookies),
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return c.ttl }),
		continueOnError: x.IfThenElseExec(conf.ContinueOnError != nil,
			func() bool { return *conf.ContinueOnError },
			func() bool { return c.continueOnError }),
		v: c.v.Merge(conf.Values),
	}, nil
}

func (c *genericContextualizer) ID() string { return c.id }

func (c *genericContextualizer) ContinueOnError() bool { return c.continueOnError }

func (c *genericContextualizer) callEndpoint(
	ctx heimdall.Context,
	sub *subject.Subject,
	values map[string]string,
	payload string,
) (*contextualizerData, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Calling contextualizer endpoint")

	req, err := c.createRequest(ctx, sub, values, payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the contextualizer endpoint timed out").
				WithErrorContext(c).
				CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the contextualizer endpoint failed").
			WithErrorContext(c).
			CausedBy(err)
	}

	defer resp.Body.Close()

	data, err := c.readResponse(ctx, resp)
	if err != nil && !errors.Is(err, errNoContent) {
		return nil, err
	}

	return &contextualizerData{Payload: data}, nil
}

func (c *genericContextualizer) createRequest(
	ctx heimdall.Context,
	sub *subject.Subject,
	values map[string]string,
	payload string,
) (*http.Request, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	endpointRenderer := endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				WithErrorContext(c).
				CausedBy(err)
		}

		return tpl.Render(map[string]any{
			"Subject": sub,
			"Values":  values,
			"Outputs": ctx.Outputs(),
		})
	})

	req, err := c.e.CreateRequest(ctx.AppContext(), strings.NewReader(payload), endpointRenderer)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(c).
			CausedBy(err)
	}

	for _, headerName := range c.fwdHeaders {
		headerValue := ctx.Request().Header(headerName)
		if len(headerValue) == 0 {
			logger.Warn().Str("_header", headerName).
				Msg("Header not present in the request but configured to be forwarded")
		} else {
			req.Header.Add(headerName, headerValue)
		}
	}

	for _, cookieName := range c.fwdCookies {
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

func (c *genericContextualizer) readResponse(ctx heimdall.Context, resp *http.Response) (any, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode).
			WithErrorContext(c)
	}

	if resp.ContentLength == 0 {
		logger.Warn().Msg("No data received from the contextualization endpoint")

		return nil, errNoContent
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(c).
			CausedBy(err)
	}

	contentType := resp.Header.Get("Content-Type")

	logger.Debug().Str("_content_type", contentType).Msg("Response received")

	decoder, err := contenttype.NewDecoder(contentType)
	if err != nil {
		logger.Warn().Str("_content_type", contentType).
			Msg("Content type is not supported. Treating it as string")

		return stringx.ToString(rawData), nil // nolint: nilerr
	}

	result, err := decoder.Decode(rawData)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			WithErrorContext(c).
			CausedBy(err)
	}

	return result, nil
}

func (c *genericContextualizer) calculateCacheKey(
	sub *subject.Subject,
	values map[string]string,
	payload string,
) string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)
	//nolint:gosec
	// no integer overflow during conversion possible
	binary.LittleEndian.PutUint64(ttlBytes, uint64(c.ttl))

	hash := sha256.New()
	hash.Write(c.e.Hash())
	hash.Write(stringx.ToBytes(c.id))
	hash.Write(stringx.ToBytes(strings.Join(c.fwdHeaders, ",")))
	hash.Write(stringx.ToBytes(strings.Join(c.fwdCookies, ",")))
	hash.Write(stringx.ToBytes(payload))
	hash.Write(ttlBytes)
	hash.Write(sub.Hash())

	for k, v := range values {
		hash.Write(stringx.ToBytes(k))
		hash.Write(stringx.ToBytes(v))
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func (c *genericContextualizer) renderTemplates(
	ctx heimdall.Context,
	sub *subject.Subject,
) (map[string]string, string, error) {
	var (
		values  map[string]string
		payload string
		err     error
	)

	if values, err = c.v.Render(map[string]any{
		"Request": ctx.Request(),
		"Subject": sub,
		"Outputs": ctx.Outputs(),
	}); err != nil {
		return nil, "", errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render values for the contextualization endpoint").
			WithErrorContext(c).
			CausedBy(err)
	}

	if c.payload != nil {
		if payload, err = c.payload.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Values":  values,
			"Outputs": ctx.Outputs(),
		}); err != nil {
			return nil, "", errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to render payload for the contextualization endpoint").
				WithErrorContext(c).
				CausedBy(err)
		}
	}

	return values, payload, nil
}
