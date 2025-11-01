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
	"errors"
	"slices"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrStepCreation = errors.New("failed to create pipeline step")

type StepDefinition struct {
	ID        string
	Condition *string
	Principal *string
	Config    config.MechanismConfig
}

func NewRuleFactory(
	repo mechanisms.Repository,
	conf *config.Configuration,
	mode config.OperationMode,
	logger zerolog.Logger,
	sdr config.SecureDefaultRule,
) (rule.Factory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{
		r:                 repo,
		l:                 logger,
		hasDefaultRule:    false,
		secureDefaultRule: bool(sdr),
		mode:              mode,
	}

	if err := rf.initWithDefaultRule(conf.Default, logger); err != nil {
		logger.Error().Err(err).Msg("Loading default rule failed")

		return nil, err
	}

	return rf, nil
}

type ruleFactory struct {
	r                 mechanisms.Repository
	l                 zerolog.Logger
	defaultRule       *ruleImpl
	hasDefaultRule    bool
	secureDefaultRule bool
	mode              config.OperationMode
}

func (f *ruleFactory) DefaultRule() rule.Rule { return f.defaultRule }
func (f *ruleFactory) HasDefaultRule() bool   { return f.hasDefaultRule }

// nolint:cyclop,funlen
func (f *ruleFactory) CreateRule(srcID string, rul v1beta1.Rule) (rule.Rule, error) {
	if f.mode == config.ProxyMode && rul.Backend == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "proxy mode requires forward_to definition")
	}

	slashesHandling := x.IfThenElse(len(rul.EncodedSlashesHandling) != 0,
		rul.EncodedSlashesHandling,
		v1beta1.EncodedSlashesOff,
	)

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(rul.Execute)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createErrorPipeline(rul.ErrorHandler)
	if err != nil {
		return nil, err
	}

	if f.defaultRule != nil {
		authenticators = x.IfThenElse(len(authenticators) != 0, authenticators, f.defaultRule.sc)
		subHandlers = x.IfThenElse(len(subHandlers) != 0, subHandlers, f.defaultRule.sh)
		finalizers = x.IfThenElse(len(finalizers) != 0, finalizers, f.defaultRule.fi)
		errorHandlers = x.IfThenElse(len(errorHandlers) != 0, errorHandlers, f.defaultRule.eh)
	}

	if len(authenticators) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "no authenticator defined")
	}

	hash, err := rul.Hash()
	if err != nil {
		return nil, err
	}

	ri := &ruleImpl{
		id:              rul.ID,
		srcID:           srcID,
		slashesHandling: slashesHandling,
		backend:         rul.Backend,
		hash:            hash,
		sc:              authenticators,
		sh:              subHandlers,
		fi:              finalizers,
		eh:              errorHandlers,
	}

	mm, err := createMethodMatcher(rul.Matcher.Methods)
	if err != nil {
		return nil, err
	}

	sm := schemeMatcher(rul.Matcher.Scheme)

	for _, rc := range rul.Matcher.Routes {
		ppm, err := createPathParamsMatcher(rc.PathParams, slashesHandling)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed creating route '%s'", rc.Path).
				CausedBy(err)
		}

		if len(rul.Matcher.Hosts) == 0 {
			rul.Matcher.Hosts = append(rul.Matcher.Hosts, "*")
		}

		for _, host := range rul.Matcher.Hosts {
			ri.routes = append(ri.routes,
				&routeImpl{
					rule:    ri,
					host:    host,
					path:    rc.Path,
					matcher: andMatcher{sm, mm, ppm},
				})
		}
	}

	return ri, nil
}

//nolint:funlen,gocognit,cyclop
func (f *ruleFactory) createExecutePipeline(steps []v1beta1.Step) (pipeline, pipeline, pipeline, error) {
	var (
		authenticatorSteps  pipeline
		subjectHandlerSteps pipeline
		finalizerSteps      pipeline
		err                 error
	)

	stepIDs := make([]string, len(steps))

	authenticatorCheck := func() error {
		if len(subjectHandlerSteps) != 0 || len(finalizerSteps) != 0 {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"an authenticator is defined after some other non authenticator type")
		}

		return nil
	}

	contextualizersCheck := func() error {
		if len(finalizerSteps) != 0 {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"at least one finalizer is defined before a contextualizer")
		}

		return nil
	}

	authorizersCheck := func() error {
		if len(finalizerSteps) != 0 {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"at least one finalizer is defined before an authorizer")
		}

		return nil
	}

	finalizersCheck := func() error { return nil }

	for idx, step := range steps {
		ref := step.MechanismReference()
		def := StepDefinition{
			ID:        step.ID,
			Condition: step.Condition,
			Principal: step.Principal,
			Config:    step.Config,
		}

		stepIDs[idx] = def.ID

		authenticatorSteps, err = buildStage(
			mechanisms.KindAuthenticator,
			ref,
			def,
			authenticatorCheck,
			authenticatorSteps,
			f.createStep,
		)
		if err == nil {
			continue
		} else if !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		}

		subjectHandlerSteps, err = buildStage(
			mechanisms.KindAuthorizer,
			ref,
			def,
			authorizersCheck,
			subjectHandlerSteps,
			f.createStep,
		)
		if err == nil {
			continue
		} else if !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		}

		subjectHandlerSteps, err = buildStage(
			mechanisms.KindContextualizer,
			ref,
			def,
			contextualizersCheck,
			subjectHandlerSteps,
			f.createStep,
		)
		if err == nil {
			continue
		} else if !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		}

		finalizerSteps, err = buildStage(
			mechanisms.KindFinalizer,
			ref,
			def,
			finalizersCheck,
			finalizerSteps,
			f.createStep,
		)
		if err == nil {
			continue
		} else if !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		}

		return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"unsupported configuration in execute")
	}

	stepIDs = slices.DeleteFunc(stepIDs, func(s string) bool { return len(s) == 0 })

	if slices.Compare(stepIDs, slices.Compact(stepIDs)) != 0 {
		return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"IDs used for execute pipeline steps must be unique")
	}

	return authenticatorSteps, subjectHandlerSteps, finalizerSteps, nil
}

func (f *ruleFactory) createErrorPipeline(steps []v1beta1.Step) (pipeline, error) {
	var (
		errorHandlers pipeline
		noop          = func() error { return nil }
		err           error
	)

	stepIDs := make([]string, len(steps))

	for idx, step := range steps {
		ref := step.MechanismReference()
		def := StepDefinition{
			ID:        step.ID,
			Condition: step.Condition,
			Principal: step.Principal,
			Config:    step.Config,
		}

		stepIDs[idx] = def.ID

		errorHandlers, err = buildStage(
			mechanisms.KindErrorHandler,
			ref,
			def,
			noop,
			errorHandlers,
			f.createStep,
		)
		if err == nil {
			continue
		} else if !errors.Is(err, errHandlerNotFound) {
			return nil, err
		}
	}

	stepIDs = slices.DeleteFunc(stepIDs, func(s string) bool { return len(s) == 0 })

	if slices.Compare(stepIDs, slices.Compact(stepIDs)) != 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"IDs used for error pipeline steps must be unique")
	}

	return errorHandlers, nil
}

func (f *ruleFactory) initWithDefaultRule(ruleConfig *config.DefaultRule, logger zerolog.Logger) error {
	if ruleConfig == nil {
		logger.Info().Msg("No default rule configured")

		f.hasDefaultRule = false

		return nil
	}

	logger.Info().Msg("Loading default rule")

	executeSteps, err := f.convertToSteps(ruleConfig.Execute)
	if err != nil {
		return err
	}

	ehSteps, err := f.convertToSteps(ruleConfig.ErrorHandler)
	if err != nil {
		return err
	}

	prinCreators, subHandlers, finalizers, err := f.createExecutePipeline(executeSteps)
	if err != nil {
		return err
	}

	errorPipeline, err := f.createErrorPipeline(ehSteps)
	if err != nil {
		return err
	}

	if len(prinCreators) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no authenticator defined for default rule")
	}

	if prinCreators[0].IsInsecure() {
		if f.secureDefaultRule {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"insecure default rule configured")
		}

		logger.Warn().Msg("Insecure default rule configured")
	}

	f.defaultRule = &ruleImpl{
		id:              "default",
		slashesHandling: v1beta1.EncodedSlashesOff,
		srcID:           "config",
		isDefault:       true,
		sc:              prinCreators,
		sh:              subHandlers,
		fi:              finalizers,
		eh:              errorPipeline,
	}

	f.hasDefaultRule = true

	return nil
}

func (f *ruleFactory) convertToSteps(rawSteps []config.MechanismConfig) ([]v1beta1.Step, error) {
	dec := encoding.NewDecoder(
		encoding.WithTagName("json"),
	)

	executeSteps := make([]v1beta1.Step, len(rawSteps))

	for idx, rawStep := range rawSteps {
		var step v1beta1.Step
		if err := dec.DecodeMap(&step, rawStep); err != nil {
			return nil, err
		}

		ref := step.MechanismReference()
		if ref.Kind == "unknown" {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unknown mechanism kind")
		}

		executeSteps[idx] = step
	}

	return executeSteps, nil
}

func (f *ruleFactory) createStep(ref v1beta1.MechanismReference, def StepDefinition) (heimdall.Step, error) {
	var (
		err       error
		mechanism mechanisms.Mechanism
	)

	switch ref.Kind {
	case "authenticator":
		mechanism, err = f.r.Authenticator(ref.Name)
	case "authorizer":
		mechanism, err = f.r.Authorizer(ref.Name)
	case "contextualizer":
		mechanism, err = f.r.Contextualizer(ref.Name)
	case "finalizer":
		mechanism, err = f.r.Finalizer(ref.Name)
	case "error_handler":
		mechanism, err = f.r.ErrorHandler(ref.Name)
	default:
		err = errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unknown mechanism kind: %s", ref.Kind)
	}

	if err != nil {
		return nil, errorchain.New(ErrStepCreation).CausedBy(err)
	}

	step, err := mechanism.CreateStep(def.ID, def.Config)
	if err != nil {
		return nil, errorchain.New(ErrStepCreation).CausedBy(err)
	}

	return step, nil
}

type CheckFunc func() error

var errHandlerNotFound = errors.New("handler not found")

func buildStage(
	expectedKind mechanisms.Kind,
	ref v1beta1.MechanismReference,
	def StepDefinition,
	check CheckFunc,
	stage pipeline,
	createHandler func(ref v1beta1.MechanismReference, def StepDefinition) (heimdall.Step, error),
) (pipeline, error) {
	if mechanisms.Kind(ref.Kind) != expectedKind {
		return stage, errHandlerNotFound
	}

	if err := check(); err != nil {
		return stage, err
	}

	handler, err := createHandler(ref, def)
	if err != nil {
		return stage, err
	}

	if def.Condition != nil {
		condition, err := getExecutionCondition(def.Condition)
		if err != nil {
			return stage, err
		}

		return append(stage, &conditionalStep{h: handler, c: condition}), nil
	}

	return append(stage, handler), nil
}

func getExecutionCondition(condition *string) (executionCondition, error) {
	if len(*condition) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"empty execution condition")
	}

	return newCelExecutionCondition(*condition)
}
