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
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
)

type ruleImpl struct {
	id                     string
	encodedSlashesHandling config.EncodedSlashesHandling
	pathExpression         string
	allowedScheme          string
	hostMatcher            PatternMatcher
	pathMatcher            PatternMatcher
	allowedMethods         []string
	backend                *config.Backend
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

	request := ctx.Request()
	if len(request.URL.RawPath) != 0 {
		// unescape captures
		captures := request.URL.Captures
		for k, v := range captures {
			captures[k] = unescape(v, r.encodedSlashesHandling)
		}

		// unescape path
		if r.encodedSlashesHandling == config.EncodedSlashesOn {
			request.URL.RawPath = ""
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

	// fastest checks first
	// match scheme
	if len(r.allowedScheme) != 0 && r.allowedScheme != request.URL.Scheme {
		logger.Debug().Msg("Allowed scheme mismatch")

		return false
	}

	// match methods
	if !slices.Contains(r.allowedMethods, request.Method) {
		logger.Debug().Msg("Allowed method mismatch")

		return false
	}

	// check encoded slash handling
	if r.encodedSlashesHandling == config.EncodedSlashesOff && strings.Contains(request.URL.RawPath, "%2F") {
		logger.Debug().Msg("Path contains encoded slashes, which is not allowed")

		return false
	}

	// match host
	if !r.hostMatcher.Match(request.URL.Host) {
		logger.Debug().Msg("Host does not satisfy configured expression")

		return false
	}

	// match path
	var path string
	if r.encodedSlashesHandling == config.EncodedSlashesOn {
		path = request.URL.Path
	} else {
		path = x.IfThenElse(len(request.URL.RawPath) != 0, request.URL.RawPath, request.URL.Path)
	}

	if !r.pathMatcher.Match(path) {
		logger.Debug().Msgf("Path %s does not satisfy configured expression", request.URL.Path)

		return false
	}

	logger.Debug().Msg("Rule matched")

	return true
}

func (r *ruleImpl) ID() string { return r.id }

func (r *ruleImpl) SrcID() string { return r.srcID }

func (r *ruleImpl) PathExpression() string { return r.pathExpression }

func (r *ruleImpl) SameAs(other rule.Rule) bool {
	return r.ID() == other.ID() && r.SrcID() == other.SrcID()
}

type backend struct {
	targetURL *url.URL
}

func (b *backend) URL() *url.URL { return b.targetURL }

func unescape(value string, handling config.EncodedSlashesHandling) string {
	switch handling {
	case config.EncodedSlashesOn:
		unescaped, _ := url.PathUnescape(value)

		return unescaped
	case config.EncodedSlashesOnNoDecode:
		unescaped := strings.ReplaceAll(value, "%2F", "$$$escaped-slash$$$")
		unescaped, _ = url.PathUnescape(unescaped)

		return strings.ReplaceAll(unescaped, "$$$escaped-slash$$$", "%2F")
	default:
		return value
	}
}
