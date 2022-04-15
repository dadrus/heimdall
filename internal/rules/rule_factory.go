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
	HasDefaultRule() bool
	DefaultRule() Rule
}

func NewRuleFactory(hf pipeline.HandlerFactory, conf config.Configuration, logger zerolog.Logger) (RuleFactory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{hf: hf, hasDefaultRule: false, logger: logger}

	if err := rf.initWithDefaultRule(conf.Rules.Default, logger); err != nil {
		logger.Error().Err(err).Msg("Loading default rule failed")

		return nil, err
	}

	return rf, nil
}

type ruleFactory struct {
	hf             pipeline.HandlerFactory
	logger         zerolog.Logger
	defaultRule    *rule
	hasDefaultRule bool
}

func (f *ruleFactory) createExecutePipeline(
	pipeline []map[string]any,
) (compositeSubjectCreator, compositeSubjectHandler, compositeSubjectHandler, error) {
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

func (f *ruleFactory) DefaultRule() Rule {
	return f.defaultRule
}

func (f *ruleFactory) HasDefaultRule() bool {
	return f.hasDefaultRule
}

func (f *ruleFactory) CreateRule(srcID string, ruleConfig config.RuleConfig) (Rule, error) {
	authenticators, subHandlers, mutators, err := f.createExecutePipeline(ruleConfig.Execute)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createOnErrorPipeline(ruleConfig.ErrorHandler)
	if err != nil {
		return nil, err
	}

	methods := ruleConfig.Methods
	if f.defaultRule != nil {
		authenticators = x.IfThenElse(len(authenticators) != 0, authenticators, f.defaultRule.sc)
		subHandlers = x.IfThenElse(len(subHandlers) != 0, subHandlers, f.defaultRule.sh)
		mutators = x.IfThenElse(len(mutators) != 0, mutators, f.defaultRule.m)
		errorHandlers = x.IfThenElse(len(errorHandlers) != 0, errorHandlers, f.defaultRule.eh)
		methods = x.IfThenElse(len(methods) != 0, methods, f.defaultRule.methods)
	}

	if len(authenticators) == 0 {
		return nil, errorchain.NewWithMessagef(config.ErrConfiguration,
			"No authenticator defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(mutators) == 0 {
		return nil, errorchain.NewWithMessagef(config.ErrConfiguration,
			"No mutator defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(methods) == 0 {
		return nil, errorchain.NewWithMessagef(config.ErrConfiguration,
			"No methods defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	strategy := x.IfThenElse(len(ruleConfig.MatchingStrategy) == 0, "glob", ruleConfig.MatchingStrategy)

	matcher, err := patternmatcher.NewPatternMatcher(strategy, ruleConfig.URL)
	if err != nil {
		return nil, err
	}

	return &rule{
		id:         ruleConfig.ID,
		urlMatcher: matcher,
		methods:    methods,
		srcID:      srcID,
		isDefault:  false,
		sc:         authenticators,
		sh:         subHandlers,
		m:          mutators,
		eh:         errorHandlers,
	}, nil
}

func (f *ruleFactory) createOnErrorPipeline(ehConfigs []map[string]any) (compositeErrorHandler, error) {
	var errorHandlers compositeErrorHandler

	for _, ehStep := range ehConfigs {
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

func (f *ruleFactory) initWithDefaultRule(ruleConfig *config.DefaultRuleConfig, logger zerolog.Logger) error {
	if ruleConfig == nil {
		logger.Info().Msg("No default rule configured")

		f.hasDefaultRule = false

		return nil
	}

	logger.Debug().Msg("Loading default rule")

	authenticators, subHandlers, mutators, err := f.createExecutePipeline(ruleConfig.Execute)
	if err != nil {
		return err
	}

	errorHandlers, err := f.createOnErrorPipeline(ruleConfig.ErrorHandler)
	if err != nil {
		return err
	}

	if len(authenticators) == 0 {
		return errorchain.NewWithMessage(config.ErrConfiguration, "No authenticator defined for default rule")
	}

	if len(mutators) == 0 {
		return errorchain.NewWithMessagef(config.ErrConfiguration, "No mutator defined for default rule")
	}

	if len(ruleConfig.Methods) == 0 {
		return errorchain.NewWithMessagef(config.ErrConfiguration, "No methods defined for default rule")
	}

	f.defaultRule = &rule{
		id:        "default",
		methods:   ruleConfig.Methods,
		srcID:     "config",
		isDefault: true,
		sc:        authenticators,
		sh:        subHandlers,
		m:         mutators,
		eh:        errorHandlers,
	}

	f.hasDefaultRule = true

	return nil
}

type rule struct {
	id         string
	urlMatcher patternmatcher.PatternMatcher
	methods    []string
	srcID      string
	isDefault  bool
	sc         compositeSubjectCreator
	sh         compositeSubjectHandler
	m          compositeSubjectHandler
	eh         compositeErrorHandler
}

func (r *rule) Execute(ctx heimdall.Context) error {
	logger := zerolog.Ctx(ctx.AppContext())

	if r.isDefault {
		logger.Debug().Msg("Executing default rule")
	} else {
		logger.Debug().Msgf("Executing rule id=%s, from src=%s", r.id, r.srcID)
	}

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
