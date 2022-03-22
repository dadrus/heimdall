package authenticators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/authenticators/config"
	"github.com/dadrus/heimdall/authenticators/extractors"
	"github.com/dadrus/heimdall/authenticators/oauth2"
)

var _ Authenticator = new(oauth2IntrospectionAuthenticator)

func newOAuth2IntrospectionAuthenticator(id string, rawConfig json.RawMessage) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint config.Endpoint   `json:"introspection_endpoint"`
		Asserter config.Assertions `json:"introspection_response_assertions"`
		Session  config.Session    `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	c.Endpoint.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	c.Endpoint.Headers["Accept-Type"] = "application/json"

	extractor := extractors.CompositeExtractor{
		extractors.HeaderExtractor{
			HeaderName:  "Authorization",
			ValuePrefix: "Bearer ",
		},
		extractors.FormExtractor("access_token"),
		extractors.QueryExtractor("access_token"),
	}

	return &oauth2IntrospectionAuthenticator{
		id: id,
		ae: extractor,
		e:  c.Endpoint,
		a:  c.Asserter,
		se: c.Session,
	}, nil
}

type oauth2IntrospectionAuthenticator struct {
	id string

	ae extractors.AuthDataExtractor
	e  config.Endpoint
	a  config.Assertions
	se config.Session
}

func (a *oauth2IntrospectionAuthenticator) Id() string {
	return a.id
}

func (a *oauth2IntrospectionAuthenticator) Authenticate(ctx context.Context, as AuthDataSource, sc *SubjectContext) error {
	accessToken, err := a.ae.Extract(as)
	if err != nil {
		return fmt.Errorf("failed to extract authentication data: %w", err)
	}

	data := url.Values{
		"token":           []string{accessToken},
		"token_type_hint": []string{"access_token"},
	}

	rawBody, err := a.e.SendRequest(ctx, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	var resp oauth2.IntrospectionResponse
	if err := json.Unmarshal(rawBody, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal introspection response: %w", err)
	}

	if err := resp.Verify(a.a); err != nil {
		return fmt.Errorf("validation of the introspection response failed: %w", err)
	}

	if sc.Subject, err = a.se.GetSubject(rawBody); err != nil {
		return err
	}

	return nil
}
