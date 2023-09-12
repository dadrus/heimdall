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

package rules

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

type ruleImpl struct {
	id         string
	urlMatcher patternmatcher.PatternMatcher
	backend    *config.Backend
	methods    []string
	srcID      string
	isDefault  bool
	hash       []byte
	sc         compositeSubjectCreator
	sh         compositeSubjectHandler
	un         compositeSubjectHandler
	eh         compositeErrorHandler
}

func (r *ruleImpl) Execute(ctx heimdall.Context) (rule.Backend, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if r.isDefault {
		logger.Info().Msg("Executing default rule")
	} else {
		logger.Info().Str("_src", r.srcID).Str("_id", r.id).Msg("Executing rule")
	}

	// authenticators
	sub, err := r.sc.Execute(ctx)
	if err != nil {
		_, err := r.eh.Execute(ctx, err)

		return nil, err
	}

	// authorizers & contextualizer
	if err = r.sh.Execute(ctx, sub); err != nil {
		_, err := r.eh.Execute(ctx, err)

		return nil, err
	}

	// unifiers
	if err = r.un.Execute(ctx, sub); err != nil {
		_, err := r.eh.Execute(ctx, err)

		return nil, err
	}

	var upstream rule.Backend

	if r.backend != nil {
		upstream = &backend{
			readTimeout:  r.backend.ReadTimeout(),
			writeTimeout: r.backend.WriteTimeout(),
			targetURL:    r.backend.CreateURL(ctx.Request().URL),
		}
	}

	return upstream, nil
}

func (r *ruleImpl) MatchesURL(requestURL *url.URL) bool {
	toBeMatched := url.URL{
		Scheme: requestURL.Scheme,
		Opaque: fmt.Sprintf("//%s%s", requestURL.Host, requestURL.Path),
	}

	return r.urlMatcher.Match(toBeMatched.String())
}

func (r *ruleImpl) MatchesMethod(method string) bool { return slices.Contains(r.methods, method) }

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }

type backend struct {
	readTimeout  *time.Duration
	writeTimeout *time.Duration
	targetURL    *url.URL
}

func (b *backend) Transport() http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, //nolint:gomnd
			KeepAlive: 30 * time.Second, //nolint:gomnd
		}).DialContext,
		MaxIdleConns:          100,              //nolint:gomnd
		IdleConnTimeout:       90 * time.Second, //nolint:gomnd
		TLSHandshakeTimeout:   10 * time.Second, //nolint:gomnd
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

func (b *backend) URL() *url.URL                { return b.targetURL }
func (b *backend) ReadTimeout() *time.Duration  { return b.readTimeout }
func (b *backend) WriteTimeout() *time.Duration { return b.writeTimeout }
