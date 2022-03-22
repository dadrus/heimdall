package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/pipeline"
)

var _ Authenticator = new(anonymousAuthenticator)

func newAnonymousAuthenticator(id string, rawConfig json.RawMessage) (*anonymousAuthenticator, error) {
	type config struct {
		Subject string `json:"subject"`
	}

	var c config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	if len(c.Subject) == 0 {
		c.Subject = "anonymous"
	}

	return &anonymousAuthenticator{
		id:        id,
		subjectId: c.Subject,
	}, nil
}

type anonymousAuthenticator struct {
	id        string
	subjectId string
}

func (a *anonymousAuthenticator) Id() string {
	return a.id
}

func (a *anonymousAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	return nil
}
