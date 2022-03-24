package authenticators

import (
	"context"
	"strings"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type AuthenticationDataAuthenticator struct {
	Endpoint         Endpoint
	SubjectExtractor SubjectExtrator
	AuthDataGetter   AuthDataGetter
}

func (a *AuthenticationDataAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *heimdall.SubjectContext) error {
	authDataRef, err := a.AuthDataGetter.GetAuthData(as)
	if err != nil {
		return &errorsx.ArgumentError{Message: "failed to extract authentication data", Cause: err}
	}

	rawBody, err := a.Endpoint.SendRequest(ctx, strings.NewReader(authDataRef))
	if err != nil {
		return err
	}

	if sc.Subject, err = a.SubjectExtractor.GetSubject(rawBody); err != nil {
		return err
	}

	return nil
}
