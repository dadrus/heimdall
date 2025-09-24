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
	"fmt"
	"slices"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/common"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func NewRuleFactory(
	hf mechanisms.MechanismFactory,
	conf *config.Configuration,
	mode config.OperationMode,
	logger zerolog.Logger,
	sdr config.SecureDefaultRule,
) (rule.Factory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{
		hf:                hf,
		hasDefaultRule:    false,
		secureDefaultRule: bool(sdr),
		logger:            logger,
		mode:              mode,
	}

	if err := rf.initWithDefaultRule(conf.Default, logger); err != nil {
		logger.Error().Err(err).Msg("Loading default rule failed")

		return nil, err
	}

	return rf, nil
}

type ruleFactory struct {
	hf                mechanisms.MechanismFactory
	logger            zerolog.Logger
	defaultRule       *ruleImpl
	hasDefaultRule    bool
	secureDefaultRule bool
	mode              config.OperationMode
}

func (f *ruleFactory) DefaultRule() rule.Rule { return f.defaultRule }
func (f *ruleFactory) HasDefaultRule() bool   { return f.hasDefaultRule }

// nolint:cyclop,funlen
func (f *ruleFactory) CreateRule(version, srcID string, rul v1beta1.Rule) (rule.Rule, error) {
	if f.mode == config.ProxyMode && rul.Backend == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "proxy mode requires forward_to definition")
	}

	slashesHandling := x.IfThenElse(len(rul.EncodedSlashesHandling) != 0,
		rul.EncodedSlashesHandling,
		common.EncodedSlashesOff,
	)

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(version, rul.Execute)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createOnErrorPipeline(version, rul.ErrorHandler)
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
func (f *ruleFactory) createExecutePipeline(
	version string,
	pipeline []config.MechanismConfig,
) (compositeSubjectCreator, compositeSubjectHandler, compositeSubjectHandler, error) {
	var (
		authenticatorSteps  compositeSubjectCreator
		subjectHandlerSteps compositeSubjectHandler
		finalizerSteps      compositeSubjectHandler
		stepIDs             []string
	)

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

	for _, pipelineStep := range pipeline {
		refID, found := pipelineStep["authenticator"]
		if found {
			if len(subjectHandlerSteps) != 0 || len(finalizerSteps) != 0 {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
					"an authenticator is defined after some other non authenticator type")
			}

			stepID := getStepID(pipelineStep["id"])

			authenticator, err := f.hf.CreateAuthenticator(
				version,
				fmt.Sprintf("%v", refID),
				stepID,
				getConfig(pipelineStep["config"]),
			)
			if err != nil {
				return nil, nil, nil, err
			}

			authenticatorSteps = append(authenticatorSteps, authenticator)
			stepIDs = append(stepIDs, stepID)

			continue
		}

		handler, stepID, err := createHandler(version, "authorizer", pipelineStep, authorizersCheck,
			f.hf.CreateAuthorizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			subjectHandlerSteps = append(subjectHandlerSteps, handler)
			stepIDs = append(stepIDs, stepID)

			continue
		}

		handler, stepID, err = createHandler(version, "contextualizer", pipelineStep, contextualizersCheck,
			f.hf.CreateContextualizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			subjectHandlerSteps = append(subjectHandlerSteps, handler)
			stepIDs = append(stepIDs, stepID)

			continue
		}

		handler, stepID, err = createHandler(version, "finalizer", pipelineStep, finalizersCheck,
			f.hf.CreateFinalizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			finalizerSteps = append(finalizerSteps, handler)
			stepIDs = append(stepIDs, stepID)

			continue
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

func (f *ruleFactory) createOnErrorPipeline(
	version string,
	ehConfigs []config.MechanismConfig,
) (compositeErrorHandler, error) {
	var (
		errorHandlers compositeErrorHandler
		stepIDs       []string
	)

	for _, ehStep := range ehConfigs {
		refID, found := ehStep["error_handler"]
		if found {
			condition, err := getExecutionCondition(ehStep["if"])
			if err != nil {
				return nil, err
			}

			stepID := getStepID(ehStep["id"])

			handler, err := f.hf.CreateErrorHandler(
				version,
				fmt.Sprintf("%v", refID),
				stepID,
				getConfig(ehStep["config"]),
			)
			if err != nil {
				return nil, err
			}

			errorHandlers = append(errorHandlers, &conditionalErrorHandler{h: handler, c: condition})
			stepIDs = append(stepIDs, stepID)
		} else {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported configuration in error handler")
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

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(
		v1beta1.Version,
		ruleConfig.Execute,
	)
	if err != nil {
		return err
	}

	errorHandlers, err := f.createOnErrorPipeline(
		v1beta1.Version,
		ruleConfig.ErrorHandler,
	)
	if err != nil {
		return err
	}

	if len(authenticators) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no authenticator defined for default rule")
	}

	if authenticators[0].IsInsecure() {
		if f.secureDefaultRule {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration, "insecure default rule configured")
		}

		logger.Warn().Msg("Insecure default rule configured")
	}

	f.defaultRule = &ruleImpl{
		id:              "default",
		slashesHandling: common.EncodedSlashesOff,
		srcID:           "config",
		isDefault:       true,
		sc:              authenticators,
		sh:              subHandlers,
		fi:              finalizers,
		eh:              errorHandlers,
	}

	f.hasDefaultRule = true

	return nil
}

type CheckFunc func() error

var errHandlerNotFound = errors.New("handler not found")

func createHandler[T subjectHandler](
	version string,
	handlerType string,
	configMap map[string]any,
	check CheckFunc,
	creteHandler func(version, refID, stepID string, conf config.MechanismConfig) (T, error),
) (subjectHandler, string, error) {
	refID, found := configMap[handlerType]
	if !found {
		return nil, "", errHandlerNotFound
	}

	if err := check(); err != nil {
		return nil, "", err
	}

	condition, err := getExecutionCondition(configMap["if"])
	if err != nil {
		return nil, "", err
	}

	stepID := getStepID(configMap["id"])

	handler, err := creteHandler(
		version,
		fmt.Sprintf("%v", refID),
		stepID,
		getConfig(configMap["config"]),
	)
	if err != nil {
		return nil, "", err
	}

	return &conditionalSubjectHandler{h: handler, c: condition}, stepID, nil
}

func getConfig(conf any) config.MechanismConfig {
	if conf == nil {
		return nil
	}

	m, ok := conf.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("unexpected type for config %T", conf))
	}

	return m
}

func getStepID(val any) string {
	if val == nil {
		return ""
	}

	return fmt.Sprintf("%v", val)
}

func getExecutionCondition(conf any) (executionCondition, error) {
	if conf == nil {
		return defaultExecutionCondition{}, nil
	}

	expression, ok := conf.(string)
	if !ok {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"unexpected type '%T' for execution condition", conf)
	}

	if len(expression) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"empty execution condition")
	}

	return newCelExecutionCondition(expression)
}
