package authenticators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/errorsx"
	"github.com/dadrus/heimdall/oauth2"
	"github.com/dadrus/heimdall/pipeline"
)

type OAuth2IntrospectionAuthenticator struct {
	AuthDataGetter   AuthDataGetter
	Endpoint         Endpoint
	SubjectExtractor SubjectExtrator
	Assertions       oauth2.Assertions
}

func (a *OAuth2IntrospectionAuthenticator) Authenticate(ctx context.Context, as pipeline.AuthDataSource, sc *pipeline.SubjectContext) error {
	accessToken, err := a.AuthDataGetter.GetAuthData(as)
	if err != nil {
		return &errorsx.ArgumentError{Message: "no access token present", Cause: err}
	}

	data := url.Values{
		"token":           []string{accessToken},
		"token_type_hint": []string{"access_token"},
	}

	rawBody, err := a.Endpoint.SendRequest(ctx, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	var resp oauth2.IntrospectionResponse
	if err = json.Unmarshal(rawBody, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal introspection response: %w", err)
	}

	if err = resp.Verify(a.Assertions); err != nil {
		return &errorsx.UnauthorizedError{
			Message: "access token does not satisfy assertion conditions",
			Cause:   err,
		}
	}

	if sc.Subject, err = a.SubjectExtractor.GetSubject(rawBody); err != nil {
		return fmt.Errorf("failed to extract subject information: %w", err)
	}

	return nil
}
