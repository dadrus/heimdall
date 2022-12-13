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
	sc          compositeSubjectCreator
	sh          compositeSubjectHandler
	m           compositeSubjectHandler
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

	// mutators
	if err = r.m.Execute(ctx, sub); err != nil {
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
