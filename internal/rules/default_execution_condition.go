package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type defaultExecutionCondition struct{}

func (c defaultExecutionCondition) CanExecute(_ heimdall.Context, _ *subject.Subject) (bool, error) {
	return true, nil
}
