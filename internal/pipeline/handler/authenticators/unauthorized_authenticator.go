package authenticators

import (
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func init() {
	handler.RegisterAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authenticator, error) {
			if typ != config.POTUnauthorized {
				return false, nil, nil
			}

			return true, newUnauthorizedAuthenticator(), nil
		})
}

type unauthorizedAuthenticator struct{}

func newUnauthorizedAuthenticator() *unauthorizedAuthenticator {
	return &unauthorizedAuthenticator{}
}

func (a *unauthorizedAuthenticator) Authenticate(_ heimdall.Context) (*subject.Subject, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrAuthentication, "denied by authenticator")
}

func (a *unauthorizedAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	// nothing can be reconfigured
	return a, nil
}
