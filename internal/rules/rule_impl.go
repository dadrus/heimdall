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
	"net/url"

	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
)

type ruleImpl struct {
	id          string
	urlMatcher  patternmatcher.PatternMatcher
	upstreamURL *url.URL
	methods     []string
	srcID       string
	isDefault   bool
	hash        []byte
	sc          compositeSubjectCreator
	sh          compositeSubjectHandler
	un          compositeSubjectHandler
	eh          compositeErrorHandler
}

func (r *ruleImpl) Execute(ctx heimdall.Context) (*url.URL, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if r.isDefault {
		logger.Debug().Msg("Executing default rule")
	} else {
		logger.Debug().Str("_src", r.srcID).Str("_id", r.id).Msg("Executing rule")
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

	return r.upstreamURL, nil
}

func (r *ruleImpl) MatchesURL(requestURL *url.URL) bool {
	return r.urlMatcher.Match(requestURL.String())
}

func (r *ruleImpl) MatchesMethod(method string) bool { return slices.Contains(r.methods, method) }

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }
