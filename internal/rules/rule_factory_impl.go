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
	"slices"
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

	if createdPipelines.execute, err = f.createExecutePipeline(rul.Execute); err != nil {
		return nil, err
	}

	if createdPipelines.err, err = f.createErrorPipeline(rul.ErrorHandler); err != nil {
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

func (f *ruleFactory) createExecutePipeline(steps []v1beta1.Step) (*executePipeline, error) {
	return createPipeline[*executePipeline](
		context.Background(),
		steps,
		newExecutePipelineBuilder(f, len(steps)),
	)
}

func (f *ruleFactory) createErrorPipeline(steps []v1beta1.Step) (*errorPipeline, error) {
	return createPipeline[*errorPipeline](
		context.Background(),
		steps,
		newErrorPipelineBuilder(f, len(steps)),
	)
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

	if createdPipelines.execute, err = f.createExecutePipeline(executeSteps); err != nil {
		return err
	}

	if createdPipelines.err, err = f.createErrorPipeline(ehSteps); err != nil {
		return err
	}

	if err = createdPipelines.validate(); err != nil {
		return err
	}

	if createdPipelines.execute.IsInsecure() {
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

type pipelineBuilder[T any] interface {
	add(step v1beta1.Step) error
	build() (T, error)
	CleanUp(ctx context.Context)
}

func createPipeline[T any](
	ctx context.Context,
	steps []v1beta1.Step,
	builder pipelineBuilder[T],
) (T, error) {
	var (
		err error
		res T
	)

	defer func() {
		if err != nil {
			builder.CleanUp(ctx)
		}
	}()

	for _, step := range steps {
		if err = builder.add(step); err != nil {
			return res, err
		}
	}

	res, err = builder.build()

	return res, err
}

type stepBuilder struct {
	f       *ruleFactory
	stepIDs []string
}

func newStepBuilder(factory *ruleFactory, capacity int) *stepBuilder {
	return &stepBuilder{
		f:       factory,
		stepIDs: make([]string, 0, capacity),
	}
}

func (b *stepBuilder) create(step v1beta1.Step, def StepDefinition) (pipeline.Step, error) {
	b.stepIDs = append(b.stepIDs, step.ID)

	return b.f.createStep(step.MechanismReference(), def)
}

func (b *stepBuilder) ensureUniqueIDs(pipelineName string) error {
	stepIDs := slices.Clone(b.stepIDs)

	stepIDs = slices.DeleteFunc(stepIDs, func(id string) bool {
		return len(id) == 0
	})

	slices.Sort(stepIDs)

	if slices.Compare(stepIDs, slices.Compact(stepIDs)) != 0 {
		return errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"IDs used for %s steps must be unique",
			pipelineName,
		)
	}

	return nil
}

type executeStepPlacement struct {
	ensure func(string, *executePipelineBuilder) error
	add    func(*executePipelineBuilder, StepDefinition, pipeline.Step)
}

type executePipelineBuilder struct {
	steps *stepBuilder

	authenticators map[string]compositePrincipalCreator
	principalOrder []string

	subjectHandlerStage stage
	finalizerStage      stage
}

func newExecutePipelineBuilder(factory *ruleFactory, capacity int) *executePipelineBuilder {
	return &executePipelineBuilder{
		steps:          newStepBuilder(factory, capacity),
		authenticators: make(map[string]compositePrincipalCreator),
		principalOrder: make([]string, 0, capacity),
	}
}

func (b *executePipelineBuilder) add(step v1beta1.Step) error {
	ref := step.MechanismReference()
	def := newExecuteStepDefinition(step)

	placement, err := executeStepPlacementFor(mechanisms.Kind(ref.Kind))
	if err != nil {
		return err
	}

	if err := placement.ensure(def.ID, b); err != nil {
		return err
	}

	createdStep, err := b.steps.create(step, def)
	if err != nil {
		return err
	}

	placement.add(b, def, createdStep)

	return nil
}

func (b *executePipelineBuilder) build() (*executePipeline, error) {
	if err := b.steps.ensureUniqueIDs("execute pipeline"); err != nil {
		return nil, err
	}

	authenticators := make(stage, 0, len(b.principalOrder))

	for _, principal := range b.principalOrder {
		authenticators = append(authenticators, b.authenticators[principal])
	}

	return newExecutePipeline(authenticators, b.subjectHandlerStage, b.finalizerStage), nil
}

func (b *executePipelineBuilder) CleanUp(ctx context.Context) {
	b.finalizerStage.CleanUp(ctx)
	b.subjectHandlerStage.CleanUp(ctx)

	for idx := len(b.principalOrder) - 1; idx >= 0; idx-- {
		b.authenticators[b.principalOrder[idx]].CleanUp(ctx)
	}
}

func (b *executePipelineBuilder) addAuthenticator(def StepDefinition, step pipeline.Step) {
	if len(b.authenticators[def.Principal]) == 0 {
		b.principalOrder = append(b.principalOrder, def.Principal)
	}

	b.authenticators[def.Principal] = append(b.authenticators[def.Principal], step)
}

func (b *executePipelineBuilder) addSubjectHandler(step pipeline.Step) {
	b.subjectHandlerStage = append(b.subjectHandlerStage, step)
}

func (b *executePipelineBuilder) addFinalizer(step pipeline.Step) {
	b.finalizerStage = append(b.finalizerStage, step)
}

func (b *executePipelineBuilder) canAddAuthenticator(id string) error {
	if len(b.subjectHandlerStage) != 0 || len(b.finalizerStage) != 0 {
		return errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"%s authenticator is defined after some other non authenticator type",
			id,
		)
	}

	return nil
}

func (b *executePipelineBuilder) canAddSubjectHandler(id string, kind mechanisms.Kind) error {
	if len(b.finalizerStage) != 0 {
		return errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"%s %s is defined after a finalizer",
			id,
			kind,
		)
	}

	return nil
}

func executeStepPlacementFor(kind mechanisms.Kind) (executeStepPlacement, error) {
	switch kind {
	case mechanisms.KindAuthenticator:
		return executeStepPlacement{
			ensure: func(id string, builder *executePipelineBuilder) error {
				return builder.canAddAuthenticator(id)
			},
			add: func(builder *executePipelineBuilder, def StepDefinition, step pipeline.Step) {
				builder.addAuthenticator(def, step)
			},
		}, nil

	case mechanisms.KindAuthorizer:
		return executeStepPlacement{
			ensure: func(id string, builder *executePipelineBuilder) error {
				return builder.canAddSubjectHandler(id, mechanisms.KindAuthorizer)
			},
			add: func(builder *executePipelineBuilder, _ StepDefinition, step pipeline.Step) {
				builder.addSubjectHandler(step)
			},
		}, nil

	case mechanisms.KindContextualizer:
		return executeStepPlacement{
			ensure: func(id string, builder *executePipelineBuilder) error {
				return builder.canAddSubjectHandler(id, mechanisms.KindContextualizer)
			},
			add: func(builder *executePipelineBuilder, _ StepDefinition, step pipeline.Step) {
				builder.addSubjectHandler(step)
			},
		}, nil

	case mechanisms.KindFinalizer:
		return executeStepPlacement{
			ensure: func(string, *executePipelineBuilder) error {
				return nil
			},
			add: func(builder *executePipelineBuilder, _ StepDefinition, step pipeline.Step) {
				builder.addFinalizer(step)
			},
		}, nil

	default:
		return executeStepPlacement{}, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"unsupported configuration in execute pipeline",
		)
	}
}

type errorPipelineBuilder struct {
	steps *stepBuilder

	errorHandlers stage
}

func newErrorPipelineBuilder(factory *ruleFactory, capacity int) *errorPipelineBuilder {
	return &errorPipelineBuilder{
		steps:         newStepBuilder(factory, capacity),
		errorHandlers: make(stage, 0, capacity),
	}
}

func (b *errorPipelineBuilder) add(step v1beta1.Step) error {
	ref := step.MechanismReference()
	if mechanisms.Kind(ref.Kind) != mechanisms.KindErrorHandler {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"unsupported configuration in error pipeline",
		)
	}

	createdStep, err := b.steps.create(step, newErrorStepDefinition(step))
	if err != nil {
		return err
	}

	b.errorHandlers = append(b.errorHandlers, createdStep)

	return nil
}

func (b *errorPipelineBuilder) build() (*errorPipeline, error) {
	if err := b.steps.ensureUniqueIDs("error pipeline"); err != nil {
		return nil, err
	}

	return newErrorPipeline(b.errorHandlers), nil
}

func (b *errorPipelineBuilder) CleanUp(ctx context.Context) {
	b.errorHandlers.CleanUp(ctx)
}

func newExecuteStepDefinition(step v1beta1.Step) StepDefinition {
	return StepDefinition{
		ID:        step.ID,
		Condition: step.Condition,
		Principal: x.IfThenElseExec(
			step.Principal != nil,
			func() string { return *step.Principal },
			func() string { return "default" },
		),
		Config: step.Config,
	}
}

func newErrorStepDefinition(step v1beta1.Step) StepDefinition {
	return StepDefinition{
		ID:        step.ID,
		Condition: step.Condition,
		Config:    step.Config,
	}
}

type executePipeline struct {
	authenticators  stage
	subjectHandlers stage
	finalizers      stage

	owned executePipelineStages
}

type executePipelineStages struct {
	authenticators  stage
	subjectHandlers stage
	finalizers      stage
}

func newExecutePipeline(
	authenticators stage,
	subjectHandlers stage,
	finalizers stage,
) *executePipeline {
	return &executePipeline{
		authenticators:  authenticators,
		subjectHandlers: subjectHandlers,
		finalizers:      finalizers,
		owned: executePipelineStages{
			authenticators:  authenticators,
			subjectHandlers: subjectHandlers,
			finalizers:      finalizers,
		},
	}
}

func (p *executePipeline) HasAuthenticator() bool {
	return len(p.authenticators) != 0
}

func (p *executePipeline) HasDefaultPrincipal() bool {
	return p.authenticators.HasDefaultPrincipal()
}

func (p *executePipeline) IsInsecure() bool {
	return p.authenticators.IsInsecure()
}

func (p *executePipeline) CleanUp(ctx context.Context) {
	p.owned.finalizers.CleanUp(ctx)
	p.owned.subjectHandlers.CleanUp(ctx)
	p.owned.authenticators.CleanUp(ctx)
}

func (p *executePipeline) withFallback(template *executePipeline) *executePipeline {
	if template == nil {
		return p
	}

	return &executePipeline{
		authenticators: x.IfThenElse(
			len(p.authenticators) != 0,
			p.authenticators,
			template.authenticators,
		),
		subjectHandlers: x.IfThenElse(
			len(p.subjectHandlers) != 0,
			p.subjectHandlers,
			template.subjectHandlers,
		),
		finalizers: x.IfThenElse(
			len(p.finalizers) != 0,
			p.finalizers,
			template.finalizers,
		),
		owned: p.owned,
	}
}

type errorPipeline struct {
	errorHandlers stage

	owned stage
}

func newErrorPipeline(errorHandlers stage) *errorPipeline {
	return &errorPipeline{
		errorHandlers: errorHandlers,
		owned:         errorHandlers,
	}
}

func (p *errorPipeline) CleanUp(ctx context.Context) {
	p.owned.CleanUp(ctx)
}

func (p *errorPipeline) withFallback(template *errorPipeline) *errorPipeline {
	if template == nil {
		return p
	}

	return &errorPipeline{
		errorHandlers: x.IfThenElse(
			len(p.errorHandlers) != 0,
			p.errorHandlers,
			template.errorHandlers,
		),
		owned: p.owned,
	}
}

type rulePipelines struct {
	execute *executePipeline
	err     *errorPipeline
}

func (p rulePipelines) CleanUp(ctx context.Context) {
	if p.err != nil {
		p.err.CleanUp(ctx)
	}

	if p.execute != nil {
		p.execute.CleanUp(ctx)
	}
}

func (p rulePipelines) withFallback(template rulePipelines) rulePipelines {
	if template.execute != nil {
		p.execute = p.execute.withFallback(template.execute)
	}

	if template.err != nil {
		p.err = p.err.withFallback(template.err)
	}

	return p
}

func (p rulePipelines) validate() error {
	if !p.execute.HasAuthenticator() {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"no authenticator defined",
		)
	}

	if !p.execute.HasDefaultPrincipal() {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"no authenticator defined which would create a default principal",
		)
	}

	return nil
}
