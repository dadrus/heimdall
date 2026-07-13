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
	"github.com/dadrus/heimdall/internal/secrets"
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
	resolver secrets.Resolver,
	conf *config.Configuration,
	mode config.OperationMode,
	logger zerolog.Logger,
	tracer trace.Tracer,
	meter metric.Meter,
	sdr config.SecureDefaultRule,
) (rule.Factory, error) {
	logger.Debug().Msg("Creating rule factory")

	rf := &ruleFactory{
		r:  repo,
		l:  logger,
		sr: resolver,
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
	sr                secrets.Resolver
	templateRule      *ruleImpl
	defaultRule       rule.Rule
	hasDefaultRule    bool
	secureDefaultRule bool
	mode              config.OperationMode
}

func (f *ruleFactory) DefaultRule() rule.Rule { return f.defaultRule }
func (f *ruleFactory) HasDefaultRule() bool   { return f.hasDefaultRule }

func (f *ruleFactory) CreateRule(
	resolver secrets.Resolver,
	source v1beta1.RuleSet,
	rul v1beta1.Rule,
) (rule.Rule, error) { //nolint:cyclop,funlen
	if f.mode == config.ProxyMode && rul.Backend == nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"proxy mode requires forward_to definition",
		)
	}

	slashesHandling := x.IfThenElse(len(rul.EncodedSlashesHandling) != 0,
		rul.EncodedSlashesHandling,
		v1beta1.EncodedSlashesOff,
	)

	createdPipelines, err := f.createPipelines(resolver, rul.Execute, rul.ErrorHandler)
	if err != nil {
		return nil, err
	}

	rulPipeline := f.applyTemplateFallback(createdPipelines)
	if err = rulPipeline.validate(); err != nil {
		return nil, err
	}

	var (
		hash   []byte
		result rule.Rule
	)

	if hash, err = rul.Hash(); err != nil {
		return nil, err
	}

	ri := newRuleImpl(
		rul.ID,
		rule.RuleSet{ID: source.ID, Name: source.Name, Provider: source.Provider},
		slashesHandling,
		rul.Backend,
		hash,
		rulPipeline,
	)

	if err = f.addRoutes(ri, rul.Matcher, slashesHandling); err != nil {
		return nil, err
	}

	result, err = newTelemetryRule(ri, f.m, f.t)

	return result, err
}

func (f *ruleFactory) applyTemplateFallback(pipelines rulePipeline) rulePipeline {
	if f.templateRule == nil {
		return pipelines
	}

	// Template pipelines are inherited but not owned by the new rule.
	// Cleanup remains tied to the originally created pipelines.
	return pipelines.inheritFrom(f.templateRule.p)
}

func (f *ruleFactory) addRoutes(
	ri *ruleImpl,
	matcher v1beta1.Matcher,
	slashesHandling v1beta1.EncodedSlashesHandling,
) error {
	http := matcher.HTTP

	mm, err := createMethodMatcher(http.Methods)
	if err != nil {
		return err
	}

	sm := schemeMatcher(http.Scheme)

	hosts := http.Hosts
	if len(hosts) == 0 {
		hosts = []string{"*"}
	}

	for _, rc := range http.Paths {
		ppm, err := createPathParamsMatcher(rc.Captures, slashesHandling)
		if err != nil {
			return errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed creating route '%s'",
				rc.Path,
			).CausedBy(err)
		}

		for _, host := range hosts {
			ri.routes = append(ri.routes,
				&routeImpl{
					rule:    ri,
					host:    strings.ToLower(host),
					path:    rc.Path,
					matcher: andMatcher{sm, mm, ppm},
				})
		}
	}

	return nil
}

func (f *ruleFactory) createPipelines(
	resolver secrets.Resolver,
	executeSteps,
	errorSteps []v1beta1.Step,
) (rulePipelineImpl, error) {
	execPipeline, err := createPipeline[*executePipeline](
		executeSteps,
		newExecutePipelineBuilder(f, resolver, len(executeSteps)),
	)
	if err != nil {
		return rulePipelineImpl{}, err
	}

	errPipeline, err := createPipeline[*errorPipeline](
		errorSteps,
		newErrorPipelineBuilder(f, resolver, len(errorSteps)),
	)
	if err != nil {
		return rulePipelineImpl{}, err
	}

	return rulePipelineImpl{
		execute: execPipeline,
		err:     errPipeline,
	}, nil
}

func newRuleImpl(
	id string,
	source rule.RuleSet,
	slashesHandling v1beta1.EncodedSlashesHandling,
	backend *v1beta1.Backend,
	hash []byte,
	rp rulePipeline,
) *ruleImpl {
	return &ruleImpl{
		id:              id,
		source:          source,
		slashesHandling: slashesHandling,
		backend:         backend,
		hash:            hash,
		p:               rp,
		subjectPool:     &sync.Pool{New: func() any { return make(pipeline.Subject, 4) }},
	}
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

	createdPipelines, err := f.createPipelines(f.sr, executeSteps, ehSteps)
	if err != nil {
		return err
	}

	if err = createdPipelines.validate(); err != nil {
		return err
	}

	if createdPipelines.execute.isInsecure() {
		if f.secureDefaultRule {
			err = errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"insecure default rule configured",
			)

			return err
		}

		logger.Warn().Msg("Insecure default rule configured")
	}

	rul := newRuleImpl(
		"default",
		rule.RuleSet{ID: "default", Name: "default", Provider: "config"},
		v1beta1.EncodedSlashesOff,
		nil,
		nil,
		createdPipelines,
	)

	rul.isDefault = true

	if f.defaultRule, err = newTelemetryRule(rul, f.m, f.t); err != nil {
		return err
	}

	f.templateRule = rul
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
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration, "unknown mechanism kind")
		}

		executeSteps[idx] = step
	}

	return executeSteps, nil
}

func (f *ruleFactory) createStep(
	resolver secrets.Resolver,
	ref v1beta1.MechanismReference,
	def StepDefinition,
) (pipeline.Step, error) {
	mechanism, err := f.lookupMechanism(ref)
	if err != nil {
		return nil, errorchain.New(ErrStepCreation).CausedBy(err)
	}

	step, err := mechanism.CreateStep(
		resolver,
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
