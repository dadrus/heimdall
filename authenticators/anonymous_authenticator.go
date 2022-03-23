package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/pipeline"
)

var _ Authenticator = new(anonymousAuthenticator)

func newAnonymousAuthenticator(id string, rawConfig json.RawMessage) (*anonymousAuthenticator, error) {
	var authenticator anonymousAuthenticator

	if err := json.Unmarshal(rawConfig, &authenticator); err != nil {
		return nil, err
	}

	authenticator.id = id
	return &authenticator, nil
}

type anonymousAuthenticator struct {
	id      string
	Subject string `json:"subject"`
}

func (a *anonymousAuthenticator) Id() string {
	return a.id
}

func (a *anonymousAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	subjectId := a.Subject
	if len(subjectId) == 0 {
		subjectId = "anonymous"
	}

	sc.Subject = &pipeline.Subject{Id: subjectId}
	return nil
}
