package rules

import (
	"net/url"

	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators"
	"github.com/dadrus/heimdall/internal/pipeline/authorizers"
	"github.com/dadrus/heimdall/internal/pipeline/errorhandlers"
	"github.com/dadrus/heimdall/internal/pipeline/hydrators"
	"github.com/dadrus/heimdall/internal/pipeline/mutators"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/x"
)

type RuleFactory interface {
	CreateRule(srcID string, ruleConfig config.RuleConfig) (Rule, error)
}

func NewRuleFactory(hf pipeline.HandlerFactory, logger zerolog.Logger) (RuleFactory, error) {
	return &ruleFactory{hf: hf, logger: logger}, nil
}

type ruleFactory struct {
	hf     pipeline.HandlerFactory
	logger zerolog.Logger
}

func (f *ruleFactory) CreateRule(srcID string, ruleConfig config.RuleConfig) (Rule, error) {
	authenticator, err := f.hf.CreateAuthenticator(ruleConfig.Authenticators)
	if err != nil {
		return nil, err
	}

	authorizer, err := f.hf.CreateAuthorizer(ruleConfig.Authorizer)
	if err != nil {
		return nil, err
	}

	hydrator, err := f.hf.CreateHydrator(ruleConfig.Hydrators)
	if err != nil {
		return nil, err
	}

	mutator, err := f.hf.CreateMutator(ruleConfig.Mutators)
	if err != nil {
		return nil, err
	}

	errorHandler, err := f.hf.CreateErrorHandler(ruleConfig.ErrorHandlers)
	if err != nil {
		return nil, err
	}

	strategy := x.IfThenElse(len(ruleConfig.MatchingStrategy) == 0, "glob", ruleConfig.MatchingStrategy)

	matcher, err := patternmatcher.NewPatternMatcher(strategy, ruleConfig.URL)
	if err != nil {
		return nil, err
	}

	return &rule{
		id:         ruleConfig.ID,
		urlMatcher: matcher,
		methods:    ruleConfig.Methods,
		srcID:      srcID,
		an:         authenticator,
		az:         authorizer,
		h:          hydrator,
		m:          mutator,
		eh:         errorHandler,
	}, nil
}

type rule struct {
	id         string
	urlMatcher patternmatcher.PatternMatcher
	methods    []string
	srcID      string
	an         authenticators.Authenticator
	az         authorizers.Authorizer
	h          hydrators.Hydrator
	m          mutators.Mutator
	eh         errorhandlers.ErrorHandler
}

func (r *rule) Execute(ctx heimdall.Context) error {
	logger := zerolog.Ctx(ctx.AppContext())

	sub, err := r.an.Authenticate(ctx)
	if err != nil {
		logger.Debug().Err(err).Msg("Authentication failed")

		_, err := r.eh.HandleError(ctx, err)

		return err
	}

	if err := r.az.Authorize(ctx, sub); err != nil {
		logger.Debug().Err(err).Msg("Authorization failed")

		_, err := r.eh.HandleError(ctx, err)

		return err
	}

	if err := r.h.Hydrate(ctx, sub); err != nil {
		logger.Debug().Err(err).Msg("Hydration failed")

		_, err := r.eh.HandleError(ctx, err)

		return err
	}

	if err := r.m.Mutate(ctx, sub); err != nil {
		logger.Debug().Err(err).Msg("Mutation failed")

		_, err := r.eh.HandleError(ctx, err)

		return err
	}

	return nil
}

func (r *rule) MatchesURL(requestURL *url.URL) bool {
	return r.urlMatcher.Match(requestURL.String())
}

func (r *rule) MatchesMethod(method string) bool {
	return slices.Contains(r.methods, method)
}

func (r *rule) ID() string {
	return r.id
}

func (r *rule) SrcID() string {
	return r.srcID
}
