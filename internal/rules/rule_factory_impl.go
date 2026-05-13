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
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
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
	tracer trace.Tracer,
	meter metric.Meter,
	sdr config.SecureDefaultRule,
) (rule.Factory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{
		r: repo,
		l: logger,
		t: x.IfThenElseExec(conf.Tracing.CoverRules,
			func() trace.Tracer { return tracer },
			func() trace.Tracer { return nooptrace.Tracer{} },
		),
		m: x.IfThenElseExec(conf.Metrics.CoverRules,
			func() metric.Meter { return meter },
			func() metric.Meter { return noopmetric.Meter{} },
		),
		templateRule:      nil,
		defaultRule:       nil,
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
	t                 trace.Tracer
	m                 metric.Meter
	templateRule      *ruleImpl
	defaultRule       rule.Rule
	hasDefaultRule    bool
	secureDefaultRule bool
	mode              config.OperationMode
}

func (f *ruleFactory) DefaultRule() rule.Rule { return f.defaultRule }
func (f *ruleFactory) HasDefaultRule() bool   { return f.hasDefaultRule }

func (f *ruleFactory) CreateRule(source v1beta1.RuleSet, rul v1beta1.Rule) (rule.Rule, error) { //nolint:cyclop,funlen
	if f.mode == config.ProxyMode && rul.Backend == nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration, "proxy mode requires forward_to definition")
	}

	slashesHandling := x.IfThenElse(len(rul.EncodedSlashesHandling) != 0,
		rul.EncodedSlashesHandling,
		v1beta1.EncodedSlashesOff,
	)

	var err error

	createdPipelines := rulePipelines{}
	cleanupOnError := true

	defer func() {
		if cleanupOnError {
			createdPipelines.CleanUp(context.Background())
		}
	}()

	if createdPipelines.execute, err = createPipeline[*executePipeline](
		context.Background(),
		rul.Execute,
		newExecutePipelineBuilder(f, len(rul.Execute)),
	); err != nil {
		return nil, err
	}

	if createdPipelines.err, err = createPipeline[*errorPipeline](
		context.Background(),
		rul.ErrorHandler,
		newErrorPipelineBuilder(f, len(rul.ErrorHandler)),
	); err != nil {
		return nil, err
	}

	rulPipelines := createdPipelines

	if f.templateRule != nil {
		// The template pipelines below are borrowed. They must not be cleaned up
		// by the rule being created. Cleanup is intentionally tied to createdPipelines.
		rulPipelines = rulPipelines.withFallback(
			rulePipelines{
				execute: &executePipeline{
					authenticators:  f.templateRule.sc,
					subjectHandlers: f.templateRule.sh,
					finalizers:      f.templateRule.fi,
				},
				err: &errorPipeline{
					errorHandlers: f.templateRule.eh,
				},
			},
		)
	}

	if err = rulPipelines.validate(); err != nil {
		return nil, err
	}

	hash, err := rul.Hash()
	if err != nil {
		return nil, err
	}

	ri := &ruleImpl{
		id:              rul.ID,
		source:          rule.RuleSet{ID: source.ID, Name: source.Name, Provider: source.Provider},
		slashesHandling: slashesHandling,
		backend:         rul.Backend,
		hash:            hash,
		sc:              rulPipelines.execute.authenticators,
		sh:              rulPipelines.execute.subjectHandlers,
		fi:              rulPipelines.execute.finalizers,
		eh:              rulPipelines.err.errorHandlers,
		subjectPool:     &sync.Pool{New: func() any { return make(pipeline.Subject, 4) }},
	}

	mm, err := createMethodMatcher(rul.Matcher.Methods)
	if err != nil {
		return nil, err
	}

	sm := schemeMatcher(rul.Matcher.Scheme)

	for _, rc := range rul.Matcher.Routes {
		ppm, err := createPathParamsMatcher(rc.PathParams, slashesHandling)
		if err != nil {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
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
					host:    strings.ToLower(host),
					path:    rc.Path,
					matcher: andMatcher{sm, mm, ppm},
				})
		}
	}

	result, err := newTelemetryRule(ri, f.m, f.t)
	if err != nil {
		return nil, err
	}

	cleanupOnError = false

	return result, nil
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

	createdPipelines := rulePipelines{}
	cleanupOnError := true

	defer func() {
		if cleanupOnError {
			createdPipelines.CleanUp(context.Background())
		}
	}()

	if createdPipelines.execute, err = createPipeline[*executePipeline](
		context.Background(),
		executeSteps,
		newExecutePipelineBuilder(f, len(executeSteps)),
	); err != nil {
		return err
	}

	if createdPipelines.err, err = createPipeline[*errorPipeline](
		context.Background(),
		ehSteps,
		newErrorPipelineBuilder(f, len(ehSteps)),
	); err != nil {
		return err
	}

	if err = createdPipelines.validate(); err != nil {
		return err
	}

	if createdPipelines.execute.isInsecure() {
		if f.secureDefaultRule {
			return errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"insecure default rule configured",
			)
		}

		logger.Warn().Msg("Insecure default rule configured")
	}

	rul := &ruleImpl{
		id:              "default",
		slashesHandling: v1beta1.EncodedSlashesOff,
		source:          rule.RuleSet{ID: "default", Name: "default", Provider: "config"},
		isDefault:       true,
		sc:              createdPipelines.execute.authenticators,
		sh:              createdPipelines.execute.subjectHandlers,
		fi:              createdPipelines.execute.finalizers,
		eh:              createdPipelines.err.errorHandlers,
		subjectPool:     &sync.Pool{New: func() any { return make(pipeline.Subject, 4) }},
	}

	f.defaultRule, err = newTelemetryRule(rul, f.m, f.t)
	if err != nil {
		return err
	}

	f.templateRule = rul
	f.hasDefaultRule = true
	cleanupOnError = false

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
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration, "unknown mechanism kind")
		}

		executeSteps[idx] = step
	}

	return executeSteps, nil
}

func (f *ruleFactory) createStep(ref v1beta1.MechanismReference, def StepDefinition) (pipeline.Step, error) {
	mechanism, err := f.lookupMechanism(ref)
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
			step.CleanUp(context.Background())

			return nil, err
		}

		step = newConditionalStep(step, condition)
	}

	if _, ok := f.t.(nooptrace.Tracer); ok {
		return step, nil
	}

	return newTelemetryStep(step, f.t), nil
}

func (f *ruleFactory) lookupMechanism(ref v1beta1.MechanismReference) (mechanisms.Mechanism, error) {
	switch ref.Kind {
	case "authenticator":
		return f.r.Authenticator(ref.Name)
	case "authorizer":
		return f.r.Authorizer(ref.Name)
	case "contextualizer":
		return f.r.Contextualizer(ref.Name)
	case "finalizer":
		return f.r.Finalizer(ref.Name)
	case "error_handler":
		return f.r.ErrorHandler(ref.Name)
	default:
		// can actually never happen
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"unknown mechanism kind: %s", ref.Kind)
	}
}
