package authenticators

import (
	"context"
	"errors"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type CompositeAuthenticator []handler.Authenticator

func (ca CompositeAuthenticator) Authenticate(
	ctx context.Context,
	reqCtx handler.RequestContext,
	subCtx *heimdall.SubjectContext,
) error {
	var err error

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

func (ca CompositeAuthenticator) WithConfig(_ []byte) (handler.Authenticator, error) {
	return nil, errors.New("reconfiguration not allowed")
}
