package rules

import (
	"context"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

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

func (p *executePipeline) CleanUp(ctx context.Context) {
	p.owned.finalizers.CleanUp(ctx)
	p.owned.subjectHandlers.CleanUp(ctx)
	p.owned.authenticators.CleanUp(ctx)
}

func (p *executePipeline) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	if err := p.authenticators.Execute(ctx, sub); err != nil {
		return err
	}

	if err := p.subjectHandlers.Execute(ctx, sub); err != nil {
		return err
	}

	return p.finalizers.Execute(ctx, sub)
}

func (p *executePipeline) hasAuthenticator() bool    { return len(p.authenticators) != 0 }
func (p *executePipeline) hasDefaultPrincipal() bool { return p.authenticators.HasDefaultPrincipal() }
func (p *executePipeline) isInsecure() bool          { return p.authenticators.IsInsecure() }

func (p *executePipeline) inheritFrom(template *executePipeline) *executePipeline {
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

func (p *errorPipeline) CleanUp(ctx context.Context) { p.owned.CleanUp(ctx) }

func (p *errorPipeline) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	return p.errorHandlers.Execute(ctx, sub)
}

func (p *errorPipeline) inheritFrom(template *errorPipeline) *errorPipeline {
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

type rulePipeline interface {
	pipeline.Pipeline

	inheritFrom(parent rulePipeline) rulePipeline
	validate() error
}

type rulePipelineImpl struct {
	execute *executePipeline
	err     *errorPipeline
}

func (p rulePipelineImpl) CleanUp(ctx context.Context) {
	if p.err != nil {
		p.err.CleanUp(ctx)
	}

	if p.execute != nil {
		p.execute.CleanUp(ctx)
	}
}

func (p rulePipelineImpl) Execute(ctx pipeline.Context, sub pipeline.Subject) error {
	if err := p.execute.Execute(ctx, sub); err != nil {
		ctx.SetError(err)

		return p.err.Execute(ctx, sub)
	}

	return nil
}

func (p rulePipelineImpl) inheritFrom(parent rulePipeline) rulePipeline {
	parentPipeline := parent.(rulePipelineImpl) //nolint:forcetypeassert

	return rulePipelineImpl{
		execute: p.execute.inheritFrom(parentPipeline.execute),
		err:     p.err.inheritFrom(parentPipeline.err),
	}
}

func (p rulePipelineImpl) validate() error {
	if !p.execute.hasAuthenticator() {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"no authenticator defined",
		)
	}

	if !p.execute.hasDefaultPrincipal() {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"no authenticator defined which would create a default principal",
		)
	}

	return nil
}
