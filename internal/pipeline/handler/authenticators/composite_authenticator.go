package authenticators

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeAuthenticator []handler.Authenticator

func (ca CompositeAuthenticator) Authenticate(
	ctx context.Context,
	reqCtx handler.RequestContext,
	subCtx *heimdall.SubjectContext,
) (err error) {
	for _, a := range ca {
		err = a.Authenticate(ctx, reqCtx, subCtx)
		if err != nil {
			// try next
			continue
		} else {
			return nil
		}
	}

	return err
}

func (ca CompositeAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
