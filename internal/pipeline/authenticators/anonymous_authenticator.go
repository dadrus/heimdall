package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type AnonymousAuthenticator struct {
	Subject string `json:"subject"`
}

func (a *AnonymousAuthenticator) Authenticate(_ context.Context, _ pipeline.AuthDataSource, sc *heimdall.SubjectContext) error {
	subjectId := a.Subject
	if len(subjectId) == 0 {
		subjectId = "anonymous"
	}

	sc.Subject = &heimdall.Subject{Id: subjectId}
	return nil
}
