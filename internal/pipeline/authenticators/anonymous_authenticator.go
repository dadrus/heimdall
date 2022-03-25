package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

func NewAnonymousAuthenticatorFromJSON(rawConfig json.RawMessage) (*anonymousAuthenticator, error) {
	var a anonymousAuthenticator

	if err := json.Unmarshal(rawConfig, &a); err != nil {
		return nil, &errorsx.ArgumentError{
			Message: "failed to unmarshal config",
			Cause:   err,
		}
	}

	if len(a.Subject) == 0 {
		a.Subject = "anonymous"
	}

	return &a, nil
}

type anonymousAuthenticator struct {
	Subject string `json:"subject"`
}

func (a *anonymousAuthenticator) Authenticate(_ context.Context, _ interfaces.AuthDataSource, sc *heimdall.SubjectContext) error {
	sc.Subject = &heimdall.Subject{Id: a.Subject}
	return nil
}
