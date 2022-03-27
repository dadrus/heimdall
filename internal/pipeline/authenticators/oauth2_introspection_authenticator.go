package authenticators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/config"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type oauth2IntrospectionAuthenticator struct {
	AuthDataGetter   AuthDataGetter
	Endpoint         Endpoint
	SubjectExtractor SubjectExtrator
	Assertions       oauth2.Assertions
}

func NewOAuth2IntrospectionAuthenticatorFromJSON(rawConfig json.RawMessage) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint   endpoint.Endpoint `json:"introspection_endpoint"`
		Assertions oauth2.Assertions `json:"introspection_response_assertions"`
		Session    config.Session    `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	c.Endpoint.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	c.Endpoint.Headers["Accept-Type"] = "application/json"

	extractor := extractors.CompositeExtractStrategy{
		extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
		extractors.FormParameterExtractStrategy{Name: "access_token"},
		extractors.QueryParameterExtractStrategy{Name: "access_token"},
	}

	return &oauth2IntrospectionAuthenticator{
		AuthDataGetter:   extractor,
		Endpoint:         c.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: &c.Session,
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) Authenticate(ctx context.Context, as interfaces.AuthDataSource, sc *heimdall.SubjectContext) error {
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

func (a *oauth2IntrospectionAuthenticator) WithConfig(config json.RawMessage) (interfaces.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		Assertions oauth2.Assertions `json:"introspection_response_assertions"`
	}

	var c _config
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, err
	}

	return &oauth2IntrospectionAuthenticator{
		Endpoint:         a.Endpoint,
		Assertions:       c.Assertions,
		SubjectExtractor: a.SubjectExtractor,
		AuthDataGetter:   a.AuthDataGetter,
	}, nil
}
