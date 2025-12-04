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
	Principal string
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

func (f *ruleFactory) CreateRule(srcID string, rul v1beta1.Rule) (rule.Rule, error) { //nolint:cyclop,funlen
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

	if !authenticators.HasDefaultPrincipal() {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no authenticator defined which would create a default principal")
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
func (f *ruleFactory) createExecutePipeline(steps []v1beta1.Step) (stage, stage, stage, error) {
	var (
		authenticatorStage  stage
		subjectHandlerStage stage
		finalizerStage      stage
	)

	stepIDs := make([]string, len(steps))

	authenticatorCheck := func(id string) error {
		if len(subjectHandlerStage) != 0 || len(finalizerStage) != 0 {
			return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"%s authenticator is defined after some other non authenticator type", id)
		}

		return nil
	}

	subjectHandlerCheck := func(id string, kind mechanisms.Kind) error {
		if len(finalizerStage) != 0 {
			return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"%s %s is defined after a finalizer", id, kind)
		}

		return nil
	}

	authn := make(map[string]compositePrincipalCreator)

	for idx, step := range steps {
		stepIDs[idx] = step.ID
		ref := step.MechanismReference()
		def := StepDefinition{
			ID:        step.ID,
			Condition: step.Condition,
			Principal: x.IfThenElseExec(step.Principal != nil,
				func() string { return *step.Principal },
				func() string { return "default" },
			),
			Config: step.Config,
		}

		switch mechanisms.Kind(ref.Kind) {
		case mechanisms.KindAuthenticator:
			if err := authenticatorCheck(def.ID); err != nil {
				return nil, nil, nil, err
			}

			step, err := f.createStep(ref, def)
			if err != nil {
				return nil, nil, nil, err
			}

			authn[def.Principal] = append(authn[def.Principal], step)
		case mechanisms.KindAuthorizer:
			if err := subjectHandlerCheck(def.ID, mechanisms.KindAuthorizer); err != nil {
				return nil, nil, nil, err
			}

			step, err := f.createStep(ref, def)
			if err != nil {
				return nil, nil, nil, err
			}

			subjectHandlerStage = append(subjectHandlerStage, step)
		case mechanisms.KindContextualizer:
			if err := subjectHandlerCheck(def.ID, mechanisms.KindContextualizer); err != nil {
				return nil, nil, nil, err
			}

			step, err := f.createStep(ref, def)
			if err != nil {
				return nil, nil, nil, err
			}

			subjectHandlerStage = append(subjectHandlerStage, step)
		case mechanisms.KindFinalizer:
			step, err := f.createStep(ref, def)
			if err != nil {
				return nil, nil, nil, err
			}

			finalizerStage = append(finalizerStage, step)
		default:
			return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported configuration in execute pipeline")
		}
	}

	stepIDs = slices.DeleteFunc(stepIDs, func(s string) bool { return len(s) == 0 })

	if slices.Compare(stepIDs, slices.Compact(stepIDs)) != 0 {
		return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"IDs used for execute pipeline steps must be unique")
	}

	for _, step := range authn {
		authenticatorStage = append(authenticatorStage, step)
	}

	return authenticatorStage, subjectHandlerStage, finalizerStage, nil
}

func (f *ruleFactory) createErrorPipeline(steps []v1beta1.Step) (stage, error) {
	stepIDs := make([]string, len(steps))
	errorHandlers := make(stage, len(steps))

	for idx, step := range steps {
		stepIDs[idx] = step.ID
		ref := step.MechanismReference()
		def := StepDefinition{
			ID:        step.ID,
			Condition: step.Condition,
			Config:    step.Config,
		}

		switch mechanisms.Kind(ref.Kind) {
		case mechanisms.KindErrorHandler:
			step, err := f.createStep(ref, def)
			if err != nil {
				return nil, err
			}

			errorHandlers[idx] = step
		default:
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported configuration in error pipeline")
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

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(executeSteps)
	if err != nil {
		return err
	}

	errorPipeline, err := f.createErrorPipeline(ehSteps)
	if err != nil {
		return err
	}

	if len(authenticators) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no authenticators defined for default rule")
	}

	if !authenticators.HasDefaultPrincipal() {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"no authenticator defined which would create a default principal")
	}

	if authenticators.IsInsecure() {
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
		sc:              authenticators,
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
		// can actually never happen
		err = errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unknown mechanism kind: %s", ref.Kind)
	}

	if err != nil {
		return nil, errorchain.New(ErrStepCreation).CausedBy(err)
	}

	step, err := mechanism.CreateStep(
		mechanisms.StepDefinition{
			ID:        def.ID,
			Config:    def.Config,
			Principal: def.Principal,
		},
	)
	if err != nil {
		return nil, errorchain.New(ErrStepCreation).CausedBy(err)
	}

	if def.Condition != nil {
		condition, err := newCelExecutionCondition(*def.Condition)
		if err != nil {
			return nil, err
		}

		return &conditionalStep{s: step, c: condition}, nil
	}

	return step, nil
}
