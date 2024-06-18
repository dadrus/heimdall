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

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
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
) (rule.Factory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{hf: hf, hasDefaultRule: false, logger: logger, mode: mode}

	if err := rf.initWithDefaultRule(conf.Default, logger); err != nil {
		logger.Error().Err(err).Msg("Loading default rule failed")

		return nil, err
	}

	return rf, nil
}

type ruleFactory struct {
	hf             mechanisms.MechanismFactory
	logger         zerolog.Logger
	defaultRule    *ruleImpl
	hasDefaultRule bool
	mode           config.OperationMode
}

//nolint:funlen,gocognit,cyclop
func (f *ruleFactory) createExecutePipeline(
	version string,
	pipeline []config.MechanismConfig,
) (compositeSubjectCreator, compositeSubjectHandler, compositeSubjectHandler, error) {
	var (
		authenticators  compositeSubjectCreator
		subjectHandlers compositeSubjectHandler
		finalizers      compositeSubjectHandler
	)

	contextualizersCheck := func() error {
		if len(finalizers) != 0 {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"at least one finalizer is defined before a contextualizer")
		}

		return nil
	}

	authorizersCheck := func() error {
		if len(finalizers) != 0 {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"at least one finalizer is defined before an authorizer")
		}

		return nil
	}

	finalizersCheck := func() error { return nil }

	for _, pipelineStep := range pipeline {
		id, found := pipelineStep["authenticator"]
		if found {
			if len(subjectHandlers) != 0 || len(finalizers) != 0 {
				return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
					"an authenticator is defined after some other non authenticator type")
			}

			authenticator, err := f.hf.CreateAuthenticator(version, id.(string), getConfig(pipelineStep["config"]))
			if err != nil {
				return nil, nil, nil, err
			}

			authenticators = append(authenticators, authenticator)

			continue
		}

		handler, err := createHandler(version, "authorizer", pipelineStep, authorizersCheck,
			f.hf.CreateAuthorizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			subjectHandlers = append(subjectHandlers, handler)

			continue
		}

		handler, err = createHandler(version, "contextualizer", pipelineStep, contextualizersCheck,
			f.hf.CreateContextualizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			subjectHandlers = append(subjectHandlers, handler)

			continue
		}

		handler, err = createHandler(version, "finalizer", pipelineStep, finalizersCheck,
			f.hf.CreateFinalizer)
		if err != nil && !errors.Is(err, errHandlerNotFound) {
			return nil, nil, nil, err
		} else if handler != nil {
			finalizers = append(finalizers, handler)

			continue
		}

		return nil, nil, nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"unsupported configuration in execute")
	}

	return authenticators, subjectHandlers, finalizers, nil
}

func (f *ruleFactory) DefaultRule() rule.Rule { return f.defaultRule }
func (f *ruleFactory) HasDefaultRule() bool   { return f.hasDefaultRule }

func (f *ruleFactory) CreateRule(version, srcID string, ruleConfig config2.Rule) (rule.Rule, error) {
	if f.mode == config.ProxyMode && ruleConfig.Backend == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "proxy mode requires forward_to definition")
	}

	slashesHandling := x.IfThenElse(
		len(ruleConfig.EncodedSlashesHandling) != 0,
		ruleConfig.EncodedSlashesHandling,
		config2.EncodedSlashesOff,
	)

	matcher, err := ruleConfig.Matcher.With.ToRequestMatcher(slashesHandling)
	if err != nil {
		return nil, err
	}

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(version, ruleConfig.Execute)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createOnErrorPipeline(version, ruleConfig.ErrorHandler)
	if err != nil {
		return nil, err
	}

	var defaultBacktracking bool

	if f.defaultRule != nil {
		authenticators = x.IfThenElse(len(authenticators) != 0, authenticators, f.defaultRule.sc)
		subHandlers = x.IfThenElse(len(subHandlers) != 0, subHandlers, f.defaultRule.sh)
		finalizers = x.IfThenElse(len(finalizers) != 0, finalizers, f.defaultRule.fi)
		errorHandlers = x.IfThenElse(len(errorHandlers) != 0, errorHandlers, f.defaultRule.eh)
		defaultBacktracking = f.defaultRule.allowsBacktracking
	}

	if len(authenticators) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "no authenticator defined")
	}

	hash, err := ruleConfig.Hash()
	if err != nil {
		return nil, err
	}

	allowsBacktracking := x.IfThenElseExec(ruleConfig.Matcher.BacktrackingEnabled != nil,
		func() bool { return *ruleConfig.Matcher.BacktrackingEnabled },
		func() bool { return defaultBacktracking })

	return &ruleImpl{
		id:                 ruleConfig.ID,
		srcID:              srcID,
		isDefault:          false,
		allowsBacktracking: allowsBacktracking,
		slashesHandling:    slashesHandling,
		matcher:            matcher,
		pathExpression:     ruleConfig.Matcher.Path,
		backend:            ruleConfig.Backend,
		hash:               hash,
		sc:                 authenticators,
		sh:                 subHandlers,
		fi:                 finalizers,
		eh:                 errorHandlers,
	}, nil
}

func (f *ruleFactory) createOnErrorPipeline(
	version string,
	ehConfigs []config.MechanismConfig,
) (compositeErrorHandler, error) {
	var errorHandlers compositeErrorHandler

	for _, ehStep := range ehConfigs {
		id, found := ehStep["error_handler"]
		if found {
			conf := getConfig(ehStep["config"])
			condition := ehStep["if"]

			if condition != nil {
				conf["if"] = condition
			}

			eh, err := f.hf.CreateErrorHandler(version, id.(string), conf)
			if err != nil {
				return nil, err
			}

			errorHandlers = append(errorHandlers, eh)
		} else {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported configuration in error handler")
		}
	}

	return errorHandlers, nil
}

func (f *ruleFactory) initWithDefaultRule(ruleConfig *config.DefaultRule, logger zerolog.Logger) error {
	if ruleConfig == nil {
		logger.Info().Msg("No default rule configured")

		f.hasDefaultRule = false

		return nil
	}

	logger.Debug().Msg("Loading default rule")

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(
		config2.CurrentRuleSetVersion,
		ruleConfig.Execute,
	)
	if err != nil {
		return err
	}

	errorHandlers, err := f.createOnErrorPipeline(
		config2.CurrentRuleSetVersion,
		ruleConfig.ErrorHandler,
	)
	if err != nil {
		return err
	}

	if len(authenticators) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no authenticator defined for default rule")
	}

	f.defaultRule = &ruleImpl{
		id:                 "default",
		slashesHandling:    config2.EncodedSlashesOff,
		srcID:              "config",
		isDefault:          true,
		allowsBacktracking: ruleConfig.BacktrackingEnabled,
		sc:                 authenticators,
		sh:                 subHandlers,
		fi:                 finalizers,
		eh:                 errorHandlers,
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
	creteHandler func(version, id string, conf config.MechanismConfig) (T, error),
) (subjectHandler, error) {
	id, found := configMap[handlerType]
	if !found {
		return nil, errHandlerNotFound
	}

	if err := check(); err != nil {
		return nil, err
	}

	condition, err := getExecutionCondition(configMap["if"])
	if err != nil {
		return nil, err
	}

	handler, err := creteHandler(version, id.(string), getConfig(configMap["config"]))
	if err != nil {
		return nil, err
	}

	return &conditionalSubjectHandler{h: handler, c: condition}, nil
}

func getConfig(conf any) config.MechanismConfig {
	if conf == nil {
		return nil
	}

	if m, ok := conf.(map[string]any); ok {
		return m
	}

	panic(fmt.Sprintf("unexpected type for config %T", conf))
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
