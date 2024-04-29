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
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleImpl struct {
	id                 string
	srcID              string
	isDefault          bool
	hash               []byte
	pathExpression     string
	matcher            config.RequestMatcher
	allowsBacktracking bool
	slashesHandling    config.EncodedSlashesHandling
	backend            *config.Backend
	sc                 compositeSubjectCreator
	sh                 compositeSubjectHandler
	fi                 compositeSubjectHandler
	eh                 compositeErrorHandler
}

func (r *ruleImpl) Execute(ctx heimdall.Context) (rule.Backend, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if r.isDefault {
		logger.Info().Msg("Executing default rule")
	} else {
		logger.Info().Str("_src", r.srcID).Str("_id", r.id).Msg("Executing rule")
	}

	request := ctx.Request()

	// unescape captures
	captures := request.URL.Captures
	for k, v := range captures {
		captures[k] = unescape(v, r.slashesHandling)
	}

	switch r.slashesHandling { //nolint:exhaustive
	case config.EncodedSlashesOn:
		// unescape path
		request.URL.RawPath = ""
	case config.EncodedSlashesOff:
		if strings.Contains(request.URL.RawPath, "%2F") {
			return nil, errorchain.NewWithMessage(heimdall.ErrArgument,
				"path contains encoded slash, which is not allowed")
		}
	}

	// authenticators
	sub, err := r.sc.Execute(ctx)
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
		upstream = &backend{
			targetURL: r.backend.CreateURL(&request.URL.URL),
		}
	}

	return upstream, nil
}

func (r *ruleImpl) Matches(ctx heimdall.Context) bool {
	request := ctx.Request()
	logger := zerolog.Ctx(ctx.AppContext()).With().Str("_source", r.srcID).Str("_id", r.id).Logger()

	logger.Debug().Msg("Matching rule")

	if err := r.matcher.Matches(request); err != nil {
		logger.Debug().Err(err).Msg("Request does not satisfy matching conditions")

		return false
	}

	logger.Debug().Msg("Rule matched")

	return true
}

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }

func (r *ruleImpl) PathExpression() string { return r.pathExpression }

func (r *ruleImpl) BacktrackingEnabled() bool { return r.allowsBacktracking }

func (r *ruleImpl) SameAs(other rule.Rule) bool {
	return r.ID() == other.ID() && r.SrcID() == other.SrcID()
}

type backend struct {
	targetURL *url.URL
}

func (b *backend) URL() *url.URL { return b.targetURL }

func unescape(value string, handling config.EncodedSlashesHandling) string {
	if handling == config.EncodedSlashesOn {
		unescaped, _ := url.PathUnescape(value)

		return unescaped
	}

	unescaped, _ := url.PathUnescape(strings.ReplaceAll(value, "%2F", "$$$escaped-slash$$$"))

	return strings.ReplaceAll(unescaped, "$$$escaped-slash$$$", "%2F")
}
