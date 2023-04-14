package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type executionCondition interface {
	CanExecute(ctx heimdall.Context, sub *subject.Subject) (bool, error)
}
