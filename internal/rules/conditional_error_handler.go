package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

type conditionalErrorHandler struct {
	h errorHandler
	c executionCondition
}

func (h *conditionalErrorHandler) Execute(ctx heimdall.Context, causeErr error) (bool, error) {
	if canExecute, err := h.c.CanExecute(ctx, nil, causeErr); err != nil {
		return false, err
	} else if canExecute {
		return h.h.Execute(ctx, nil)
	}

	return false, nil
}
