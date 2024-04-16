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
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type alwaysMatcher struct{}

func (alwaysMatcher) Match(_ string) bool { return true }

func NewRuleFactory(
	hf mechanisms.Factory,
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
	hf             mechanisms.Factory
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

//nolint:cyclop, funlen
func (f *ruleFactory) CreateRule(version, srcID string, ruleConfig config2.Rule) (
	rule.Rule, error,
) {
	if len(ruleConfig.ID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"no ID defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(ruleConfig.Matcher.Path.Expression) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"no path matching expression defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(ruleConfig.Matcher.HostGlob) != 0 && len(ruleConfig.Matcher.HostRegex) != 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"host glob and regex expressions are defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(ruleConfig.Matcher.Path.Glob) != 0 && len(ruleConfig.Matcher.Path.Regex) != 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"path glob and regex expressions are defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if f.mode == config.ProxyMode {
		if err := checkProxyModeApplicability(srcID, ruleConfig); err != nil {
			return nil, err
		}
	}

	var (
		hostMatcher PatternMatcher
		pathMatcher PatternMatcher
		err         error
	)

	switch {
	case len(ruleConfig.Matcher.HostGlob) != 0:
		hostMatcher, err = newGlobMatcher(ruleConfig.Matcher.HostGlob, '.')
	case len(ruleConfig.Matcher.HostRegex) != 0:
		hostMatcher, err = newRegexMatcher(ruleConfig.Matcher.HostRegex)
	default:
		hostMatcher = alwaysMatcher{}
	}

	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"filed to compile host pattern defined for rule ID=%s from %s", ruleConfig.ID, srcID).CausedBy(err)
	}

	switch {
	case len(ruleConfig.Matcher.Path.Glob) != 0:
		pathMatcher, err = newGlobMatcher(ruleConfig.Matcher.Path.Glob, '/')
	case len(ruleConfig.Matcher.Path.Regex) != 0:
		pathMatcher, err = newRegexMatcher(ruleConfig.Matcher.Path.Regex)
	default:
		pathMatcher = alwaysMatcher{}
	}

	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"filed to compile path pattern defined for rule ID=%s from %s", ruleConfig.ID, srcID).CausedBy(err)
	}

	authenticators, subHandlers, finalizers, err := f.createExecutePipeline(version, ruleConfig.Execute)
	if err != nil {
		return nil, err
	}

	errorHandlers, err := f.createOnErrorPipeline(version, ruleConfig.ErrorHandler)
	if err != nil {
		return nil, err
	}

	methods, err := expandHTTPMethods(ruleConfig.Matcher.Methods)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to expand allowed HTTP methods for rule ID=%s from %s", ruleConfig.ID, srcID).CausedBy(err)
	}

	if f.defaultRule != nil {
		authenticators = x.IfThenElse(len(authenticators) != 0, authenticators, f.defaultRule.sc)
		subHandlers = x.IfThenElse(len(subHandlers) != 0, subHandlers, f.defaultRule.sh)
		finalizers = x.IfThenElse(len(finalizers) != 0, finalizers, f.defaultRule.fi)
		errorHandlers = x.IfThenElse(len(errorHandlers) != 0, errorHandlers, f.defaultRule.eh)
		methods = x.IfThenElse(len(methods) != 0, methods, f.defaultRule.allowedMethods)
	}

	if len(authenticators) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"no authenticator defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	if len(methods) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"no methods defined for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	hash, err := f.createHash(ruleConfig)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to create hash for rule ID=%s from %s", ruleConfig.ID, srcID)
	}

	return &ruleImpl{
		id:        ruleConfig.ID,
		srcID:     srcID,
		isDefault: false,
		encodedSlashesHandling: x.IfThenElse(
			len(ruleConfig.EncodedSlashesHandling) != 0,
			ruleConfig.EncodedSlashesHandling,
			config2.EncodedSlashesOff,
		),
		allowedScheme:  ruleConfig.Matcher.Scheme,
		allowedMethods: methods,
		hostMatcher:    hostMatcher,
		pathMatcher:    pathMatcher,
		pathExpression: ruleConfig.Matcher.Path.Expression,
		backend:        ruleConfig.Backend,
		hash:           hash,
		sc:             authenticators,
		sh:             subHandlers,
		fi:             finalizers,
		eh:             errorHandlers,
	}, nil
}

func checkProxyModeApplicability(srcID string, ruleConfig config2.Rule) error {
	if ruleConfig.Backend == nil {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"heimdall is operated in proxy mode, but no forward_to is defined in rule ID=%s from %s",
			ruleConfig.ID, srcID)
	}

	if len(ruleConfig.Backend.Host) == 0 {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"missing host definition in forward_to in rule ID=%s from %s",
			ruleConfig.ID, srcID)
	}

	urlRewriter := ruleConfig.Backend.URLRewriter
	if urlRewriter == nil {
		return nil
	}

	if len(urlRewriter.Scheme) == 0 &&
		len(urlRewriter.PathPrefixToAdd) == 0 &&
		len(urlRewriter.PathPrefixToCut) == 0 &&
		len(urlRewriter.QueryParamsToRemove) == 0 {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"rewrite is defined in forward_to in rule ID=%s from %s, but is empty", ruleConfig.ID, srcID)
	}

	return nil
}

func (f *ruleFactory) createHash(ruleConfig config2.Rule) ([]byte, error) {
	rawRuleConfig, err := json.Marshal(ruleConfig)
	if err != nil {
		return nil, err
	}

	md := crypto.SHA256.New()
	md.Write(rawRuleConfig)

	return md.Sum(nil), nil
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

	methods, err := expandHTTPMethods(ruleConfig.Methods)
	if err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration, "failed to expand allowed HTTP methods").
			CausedBy(err)
	}

	if len(methods) == 0 {
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration, "no methods defined for default rule")
	}

	f.defaultRule = &ruleImpl{
		id:                     "default",
		encodedSlashesHandling: config2.EncodedSlashesOff,
		allowedMethods:         methods,
		srcID:                  "config",
		isDefault:              true,
		sc:                     authenticators,
		sh:                     subHandlers,
		fi:                     finalizers,
		eh:                     errorHandlers,
	}

	f.hasDefaultRule = true

	return nil
}

func expandHTTPMethods(methods []string) ([]string, error) {
	if slices.Contains(methods, "ALL") {
		methods = slices.DeleteFunc(methods, func(method string) bool { return method == "ALL" })

		methods = append(methods,
			http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace)
	}

	slices.SortFunc(methods, strings.Compare)

	methods = slices.Compact(methods)
	if res := slicex.Filter(methods, func(s string) bool { return len(s) == 0 }); len(res) != 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"methods list contains empty values. have you forgotten to put the corresponding value into braces?")
	}

	tbr := slicex.Filter(methods, func(s string) bool { return strings.HasPrefix(s, "!") })
	methods = slicex.Subtract(methods, tbr)
	tbr = slicex.Map[string, string](tbr, func(s string) string { return strings.TrimPrefix(s, "!") })

	return slicex.Subtract(methods, tbr), nil
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
