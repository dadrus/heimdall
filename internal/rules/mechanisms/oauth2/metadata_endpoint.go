// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type MetadataEndpoint struct {
	endpoint.Endpoint `mapstructure:",squash"`

	DisableIssuerIdentifierVerification bool `mapstructure:"disable_issuer_identifier_verification"`
}

func (e *MetadataEndpoint) init() {
	if e.Headers == nil {
		e.Headers = make(map[string]string)
	}

	if _, ok := e.Headers["Accept"]; !ok {
		e.Headers["Accept"] = "application/json"
	}

	if len(e.Method) == 0 {
		e.Method = http.MethodGet
	}

	if e.HTTPCache == nil {
		e.HTTPCache = &endpoint.HTTPCache{Enabled: true, DefaultTTL: 30 * time.Minute} //nolint:mnd
	}
}

func (e *MetadataEndpoint) Get(ctx context.Context, args map[string]any) (ServerMetadata, error) {
	e.init()

	req, err := e.CreateRequest(ctx, nil, endpoint.RenderFunc(func(value string) (string, error) {
		tpl, err := template.New(value)
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template").
				CausedBy(err)
		}

		return tpl.Render(args)
	}))
	if err != nil {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed creating oauth2 server metadata request").CausedBy(err)
	}

	resp, err := e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to oauth2 server metadata endpoint timed out").CausedBy(err)
		}

		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to oauth2 server metadata endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return ServerMetadata{}, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
	}

	sm, err := e.decodeResponse(resp)
	if err != nil {
		return ServerMetadata{}, err
	}

	if !e.DisableIssuerIdentifierVerification {
		if err = sm.verify(req.URL.String()); err != nil {
			return ServerMetadata{}, err
		}
	}

	return sm, nil
}

func (e *MetadataEndpoint) decodeResponse(resp *http.Response) (ServerMetadata, error) {
	type metadata struct {
		Issuer                   string `json:"issuer"`
		JWKSEndpointURL          string `json:"jwks_uri"`
		IntrospectionEndpointURL string `json:"introspection_endpoint"`
	}

	var spec metadata
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to unmarshal received oauth2 server metadata document").CausedBy(err)
	}

	if strings.Contains(spec.JWKSEndpointURL, "{{") &&
		strings.Contains(spec.JWKSEndpointURL, "}}") {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"received jwks_uri contains a template, which is not allowed")
	}

	if strings.Contains(spec.IntrospectionEndpointURL, "{{") &&
		strings.Contains(spec.IntrospectionEndpointURL, "}}") {
		return ServerMetadata{}, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"received introspection_endpoint contains a template, which is not allowed")
	}

	var (
		jwksEP          *endpoint.Endpoint
		introspectionEP *endpoint.Endpoint
	)

	if len(spec.JWKSEndpointURL) != 0 {
		jwksEP = &endpoint.Endpoint{
			URL:     spec.JWKSEndpointURL,
			Method:  http.MethodGet,
			Headers: map[string]string{"Accept": "application/json"},
		}
	}

	if len(spec.IntrospectionEndpointURL) != 0 {
		introspectionEP = &endpoint.Endpoint{
			URL:    spec.IntrospectionEndpointURL,
			Method: http.MethodPost,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept":       "application/json",
			},
		}
	}

	return ServerMetadata{
		Issuer:                spec.Issuer,
		JWKSEndpoint:          jwksEP,
		IntrospectionEndpoint: introspectionEP,
	}, nil
}
