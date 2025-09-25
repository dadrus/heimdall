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
	"bytes"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/common"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleImpl struct {
	id              string
	srcID           string
	isDefault       bool
	hash            []byte
	routes          []rule.Route
	slashesHandling common.EncodedSlashesHandling
	backend         *v1beta1.Backend
	sc              compositeSubjectCreator
	sh              compositeSubjectHandler
	fi              compositeSubjectHandler
	eh              compositeErrorHandler
}

func (r *ruleImpl) Execute(ctx heimdall.RequestContext) (rule.Backend, error) {
	logger := zerolog.Ctx(ctx.Context())

	if r.isDefault {
		logger.Info().Msg("Executing default rule")
	} else {
		logger.Info().Str("_src", r.srcID).Str("_id", r.id).Msg("Executing rule")
	}

	request := ctx.Request()

	switch r.slashesHandling { //nolint:exhaustive
	case common.EncodedSlashesOn:
		// unescape path
		request.URL.RawPath = ""
	case common.EncodedSlashesOff:
		if strings.Contains(request.URL.RawPath, "%2F") {
			return nil, errorchain.NewWithMessage(heimdall.ErrArgument,
				"path contains encoded slash, which is not allowed")
		}
	}

	// unescape captures
	captures := request.URL.Captures
	for k, v := range captures {
		captures[k] = unescape(v, r.slashesHandling)
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

	return r.createBackend(request), nil
}

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }

func (r *ruleImpl) SameAs(other rule.Rule) bool {
	return r.ID() == other.ID() && r.SrcID() == other.SrcID()
}

func (r *ruleImpl) Routes() []rule.Route { return r.routes }

func (r *ruleImpl) EqualTo(other rule.Rule) bool {
	return r.ID() == other.ID() &&
		r.SrcID() == other.SrcID() &&
		bytes.Equal(r.hash, other.(*ruleImpl).hash) // nolint: forcetypeassert
}

func (r *ruleImpl) createBackend(request *heimdall.Request) rule.Backend {
	var upstream rule.Backend

	if r.backend != nil {
		upstream = backend{
			targetURL: r.backend.CreateURL(&request.URL.URL),
			forwardHostHeader: r.backend.ForwardHostHeader == nil ||
				(r.backend.ForwardHostHeader != nil && *r.backend.ForwardHostHeader),
		}
	}

	return upstream
}

type routeImpl struct {
	rule    *ruleImpl
	host    string
	path    string
	matcher RouteMatcher
}

func (r *routeImpl) Matches(ctx heimdall.RequestContext, keys, values []string) bool {
	logger := zerolog.Ctx(ctx.Context()).With().
		Str("_source", r.rule.srcID).
		Str("_id", r.rule.id).
		Str("route", r.path).
		Logger()

	logger.Debug().Msg("Matching rule")

	if err := r.matcher.Matches(ctx.Request(), keys, values); err != nil {
		logger.Debug().Err(err).Msg("Request does not satisfy matching conditions")

		return false
	}

	logger.Debug().Msg("Rule matched")

	return true
}

func (r *routeImpl) Host() string { return r.host }

func (r *routeImpl) Path() string { return r.path }

func (r *routeImpl) Rule() rule.Rule { return r.rule }

type backend struct {
	targetURL         *url.URL
	forwardHostHeader bool
}

func (b backend) URL() *url.URL { return b.targetURL }

func (b backend) ForwardHostHeader() bool { return b.forwardHostHeader }

func unescape(value string, handling common.EncodedSlashesHandling) string {
	if handling == common.EncodedSlashesOn {
		unescaped, _ := url.PathUnescape(value)

		return unescaped
	}

	unescaped, _ := url.PathUnescape(strings.ReplaceAll(value, "%2F", "$$$escaped-slash$$$"))

	return strings.ReplaceAll(unescaped, "$$$escaped-slash$$$", "%2F")
}
