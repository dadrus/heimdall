package authenticators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeAuthenticator []handler.Authenticator

func (ca CompositeAuthenticator) Authenticate(ctx heimdall.Context) (sub *subject.Subject, err error) {
	for _, a := range ca {
		sub, err = a.Authenticate(ctx)
		if err != nil {
			// try next
			continue
		} else {
			return sub, nil
		}
	}

	return nil, err
}

func (ca CompositeAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
