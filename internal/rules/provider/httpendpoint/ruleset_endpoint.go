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

package httpendpoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetEndpoint struct {
	endpoint.Endpoint `mapstructure:",squash"  validate:"required"`
}

func (e *ruleSetEndpoint) ID() string { return e.URL }

func (e *ruleSetEndpoint) FetchRuleSet(ctx context.Context, validator validation.Validator) (*config.RuleSet, error) {
	req, err := e.CreateRequest(ctx, nil, nil)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			CausedBy(err)
	}

	client := e.CreateClient(req.URL.Hostname())

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to rule set endpoint timed out").
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to rule set endpoint failed").
			CausedBy(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode)
	}

	md := sha256.New()

	ruleSet, err := config.ParseRules(validator, resp.Header.Get("Content-Type"), io.TeeReader(resp.Body, md), false)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to parse received rule set").
			CausedBy(err)
	}

	ruleSet.Hash = md.Sum(nil)
	ruleSet.Source = "http_endpoint:" + e.ID()
	ruleSet.ModTime = time.Now()

	return ruleSet, nil
}

func (e *ruleSetEndpoint) init() {
	e.Method = http.MethodGet

	if e.HTTPCache == nil {
		e.HTTPCache = &endpoint.HTTPCache{Enabled: true}
	}
}
