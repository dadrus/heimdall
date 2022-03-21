package authenticators

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/authenticators/config"
)

var _ Authenticator = new(oauth2IntrospectionAuthenticator)

func newOAuth2IntrospectionAuthenticator(id string, rawConfig json.RawMessage) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint config.Endpoint `json:"introspection_endpoint"`
		Asserter config.Asserter `json:"introspection_response_assertions"`
		Session  config.Session  `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	client, err := c.Endpoint.Client()
	if err != nil {
		return nil, err
	}

	as, err := c.Endpoint.AuthenticationStrategy()
	if err != nil {
		return nil, err
	}

	return &oauth2IntrospectionAuthenticator{
		id: id,
	}, nil
}

type oauth2IntrospectionAuthenticator struct {
	id string
}

func (a *oauth2IntrospectionAuthenticator) Id() string {
	return a.id
}

func (*oauth2IntrospectionAuthenticator) Authenticate(ctx context.Context, as AuthDataSource, sc *SubjectContext) error {
	return nil
}
