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
	"net/url"
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/subject"
)

type ruleImpl struct {
	id                     string
	encodedSlashesHandling config.EncodedSlashesHandling
	urlMatcher             patternmatcher.PatternMatcher
	backend                *config.Backend
	methods                []string
	srcID                  string
	isDefault              bool
	hash                   []byte
	sc                     compositeSubjectCreator
	sh                     compositeSubjectHandler
	fi                     compositeSubjectHandler
	eh                     compositeErrorHandler
}

func (r *ruleImpl) Execute(ctx heimdall.Context) (rule.Backend, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if r.isDefault {
		logger.Info().Msg("Executing default rule")
	} else {
		logger.Info().Str("_src", r.srcID).Str("_id", r.id).Msg("Executing rule")
	}

	sub := subject.Subject{}

	// authenticators
	err := r.sc.Execute(ctx, sub)
	if err != nil {
		return nil, r.eh.Execute(ctx, err)
	}

	// authorizers & contextualizer
	if err = r.sh.Execute(ctx, sub); err != nil {
		return nil, r.eh.Execute(ctx, err)
	}

	// finalizers
	if err = r.fi.Execute(ctx, sub); err != nil {
		return nil, r.eh.Execute(ctx, err)
	}

	var upstream rule.Backend

	if r.backend != nil {
		targetURL := *ctx.Request().URL
		if r.encodedSlashesHandling == config.EncodedSlashesOn && len(targetURL.RawPath) != 0 {
			targetURL.RawPath = ""
		}

		upstream = &backend{
			targetURL: r.backend.CreateURL(&targetURL),
		}
	}

	return upstream, nil
}

func (r *ruleImpl) MatchesURL(requestURL *url.URL) bool {
	var path string

	switch r.encodedSlashesHandling {
	case config.EncodedSlashesOff:
		if strings.Contains(requestURL.RawPath, "%2F") {
			return false
		}

		path = requestURL.Path
	case config.EncodedSlashesNoDecode:
		if len(requestURL.RawPath) != 0 {
			path = strings.ReplaceAll(requestURL.RawPath, "%2F", "$$$escaped-slash$$$")
			path, _ = url.PathUnescape(path)
			path = strings.ReplaceAll(path, "$$$escaped-slash$$$", "%2F")

			break
		}

		fallthrough
	default:
		path = requestURL.Path
	}

	return r.urlMatcher.Match(fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, path))
}

func (r *ruleImpl) MatchesMethod(method string) bool { return slices.Contains(r.methods, method) }

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }

type backend struct {
	targetURL *url.URL
}

func (b *backend) URL() *url.URL { return b.targetURL }
