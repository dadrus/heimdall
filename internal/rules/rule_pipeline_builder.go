package rules

import (
	"context"
	"slices"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

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
