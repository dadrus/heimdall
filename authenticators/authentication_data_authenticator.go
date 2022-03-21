package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/authenticators/config"
	"github.com/dadrus/heimdall/authenticators/extractors"
	"github.com/dadrus/heimdall/authenticators/request_authentication_strategy"
)

var _ Authenticator = new(authenticationDataAuthenticator)

func newAuthenticationDataAuthenticator(id string, rawConfig json.RawMessage) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       config.Endpoint                 `json:"identity_info_endpoint"`
		AuthDataSource config.AuthenticationDataSource `json:"authentication_data_source"`
		Session        config.Session                  `json:"session"`
	}

	var c _config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	extractor, err := c.AuthDataSource.Extractor()
	if err != nil {
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

	return &authenticationDataAuthenticator{
		id:                   id,
		authDataExtractor:    extractor,
		client:               client,
		authStrategy:         as,
		subjectDataExtractor: c.Session,
	}, nil
}

type authenticationDataAuthenticator struct {
	id string

	address              string
	method               string
	subjectDataExtractor config.Session
	authDataExtractor    extractors.AuthDataExtractor
	authStrategy         request_authentication_strategy.AuthenticationStrategy
	client               *http.Client
}

func (a *authenticationDataAuthenticator) Id() string {
	return a.id
}

func (a *authenticationDataAuthenticator) Authenticate(ctx context.Context, as AuthDataSource, sc *SubjectContext) error {
	authDataRef, err := a.authDataExtractor.Extract(as)
	if err != nil {
		return fmt.Errorf("failed to extract authentication data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, a.method, a.address, strings.NewReader(authDataRef))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	err = a.authStrategy.Apply(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to authenticate request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	rawBody, err := a.readResponse(resp)
	if err != nil {
		return err
	}

	if sc.Subject.Id, err = a.subjectDataExtractor.SubjectId(rawBody); err != nil {
		return err
	}

	if sc.Subject.Attributes, err = a.subjectDataExtractor.SubjectAttributes(rawBody); err != nil {
		return err
	}

	return nil
}

func (*authenticationDataAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		return rawData, nil
	} else {
		return nil, errors.New(fmt.Sprintf("unexpected response. code: %v", resp.StatusCode))
	}
}
