package rules

import (
	"errors"
	"net/url"

	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrUnsupportedPipelineObject = errors.New("unsupported pipeline object")

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

func (f *ruleFactory) createExecutePipeline(
	pipeline []map[string]any,
) (subjectCreator, subjectHandler, subjectHandler, error) {
	var (
		authenticators  compositeSubjectCreator
		subjectHandlers compositeSubjectHandler
		mutators        compositeSubjectHandler
	)

	for _, pipelineStep := range pipeline {
		id, found := pipelineStep["authenticator"]
		if found {
			stepID, ok := id.(string)
			if !ok {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to convert rule step identifier to string")
			}

			authenticator, err := f.hf.CreateAuthenticator(stepID, pipelineStep["config"])
			if err != nil {
				return nil, nil, nil, err
			}

			if len(subjectHandlers) != 0 {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
					"malformed execute configuration")
			}

			authenticators = append(authenticators, authenticator)

			continue
		}

		id, found = pipelineStep["authorizer"]
		if found {
			stepID, ok := id.(string)
			if !ok {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to convert rule step identifier to string")
			}

			authorizer, err := f.hf.CreateAuthorizer(stepID, pipelineStep["config"])
			if err != nil {
				return nil, nil, nil, err
			}

			subjectHandlers = append(subjectHandlers, authorizer)

			continue
		}

		id, found = pipelineStep["hydrator"]
		if found {
			stepID, ok := id.(string)
			if !ok {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to convert rule step identifier to string")
			}

			hydrator, err := f.hf.CreateHydrator(stepID, pipelineStep["config"])
			if err != nil {
				return nil, nil, nil, err
			}

			subjectHandlers = append(subjectHandlers, hydrator)

			continue
		}

		id, found = pipelineStep["mutator"]
		if found {
			stepID, ok := id.(string)
			if !ok {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to convert rule step identifier to string")
			}

			mutator, err := f.hf.CreateMutator(stepID, pipelineStep["config"])
			if err != nil {
				return nil, nil, nil, err
			}

			mutators = append(mutators, mutator)

			continue
		}

		return nil, nil, nil, errorchain.NewWithMessagef(ErrUnsupportedPipelineObject, "%s", pipelineStep)
	}

	return authenticators, subjectHandlers, mutators, nil
}

func (f *ruleFactory) CreateRule(srcID string, ruleConfig config.RuleConfig) (Rule, error) {
	authenticator, subHandler, mutator, err := f.createExecutePipeline(ruleConfig.Pipeline)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createOnErrorPipeline(ruleConfig)
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
		sc:         authenticator,
		sh:         subHandler,
		m:          mutator,
		eh:         errorHandlers,
	}, nil
}

func (f *ruleFactory) createOnErrorPipeline(ruleConfig config.RuleConfig) (errorHandler, error) {
	var errorHandlers compositeErrorHandler

	for _, ehStep := range ruleConfig.ErrorHandler {
		id, found := ehStep["error_handler"]
		if found {
			stepID, ok := id.(string)
			if !ok {
				return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to convert rule step identifier to string")
			}

			eh, err := f.hf.CreateErrorHandler(stepID, ehStep["config"])
			if err != nil {
				return nil, err
			}

			errorHandlers = append(errorHandlers, eh)
		} else {
			return nil, errorchain.NewWithMessagef(ErrUnsupportedPipelineObject, "%s", ehStep)
		}
	}

	return errorHandlers, nil
}

type rule struct {
	id         string
	urlMatcher patternmatcher.PatternMatcher
	methods    []string
	srcID      string
	sc         subjectCreator
	sh         subjectHandler
	m          subjectHandler
	eh         errorHandler
}

func (r *rule) Execute(ctx heimdall.Context) error {
	// authenticators
	sub, err := r.sc.Execute(ctx)
	if err != nil {
		_, err := r.eh.Execute(ctx, err)

		return err
	}

	// authorizers & hydrators
	if err := r.sh.Execute(ctx, sub); err != nil {
		_, err := r.eh.Execute(ctx, err)

		return err
	}

	// mutators
	if err := r.m.Execute(ctx, sub); err != nil {
		_, err := r.eh.Execute(ctx, err)

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
