package authenticators

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type CompositeAuthenticator []handler.Authenticator

func (ca CompositeAuthenticator) Authenticate(c context.Context, ads handler.RequestContext, sc *heimdall.SubjectContext) error {
	var err error
	for _, a := range ca {
		err = a.Authenticate(c, ads, sc)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}
	return err
}

func (ca CompositeAuthenticator) WithConfig(_ json.RawMessage) (handler.Authenticator, error) {
	return nil, errors.New("reconfiguration not allowed")
}
