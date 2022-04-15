package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type subjectHandler interface {
	Execute(heimdall.Context, *subject.Subject) error
}
