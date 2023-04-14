package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type conditionalSubjectHandler struct {
	h subjectHandler
	c executionCondition
}

func (h *conditionalSubjectHandler) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	if canExecute, err := h.c.CanExecute(ctx, sub); err != nil {
		return err
	} else if canExecute {
		return h.h.Execute(ctx, sub)
	}

	return nil
}

func (h *conditionalSubjectHandler) ContinueOnError() bool { return h.h.ContinueOnError() }
