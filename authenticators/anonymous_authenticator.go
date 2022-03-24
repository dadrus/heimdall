package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/pipeline"
)

type AnonymousAuthenticator struct {
	Subject string `json:"subject"`
}

func (a *AnonymousAuthenticator) Authenticate(_ context.Context, _ pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	subjectId := a.Subject
	if len(subjectId) == 0 {
		subjectId = "anonymous"
	}

	sc.Subject = &pipeline.Subject{Id: subjectId}
	return nil
}
