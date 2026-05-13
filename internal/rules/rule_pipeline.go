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

func (p *executePipeline) hasAuthenticator() bool    { return len(p.authenticators) != 0 }
func (p *executePipeline) hasDefaultPrincipal() bool { return p.authenticators.HasDefaultPrincipal() }
func (p *executePipeline) isInsecure() bool          { return p.authenticators.IsInsecure() }

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

func (p *errorPipeline) CleanUp(ctx context.Context) { p.owned.CleanUp(ctx) }

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
