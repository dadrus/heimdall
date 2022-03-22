package request_authentication_strategy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dadrus/heimdall/oauth2"
	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/x/httpx"
)

func NewClientCredentialsStrategy(raw json.RawMessage) (*clientCredentialsStrategy, error) {
	type config struct {
		ClientId     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
		TokenUrl     string   `json:"token_url"`
	}

	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	return &clientCredentialsStrategy{
		clientId:     c.ClientId,
		clientSecret: c.ClientSecret,
		scopes:       c.Scopes,
		tokenUrl:     c.TokenUrl,
		mutex:        &sync.RWMutex{},
	}, nil
}

type clientCredentialsStrategy struct {
	clientId     string
	clientSecret string
	scopes       []string
	tokenUrl     string

	lastResponse *oauth2.TokenEndpointResponse
	mutex        *sync.RWMutex
}

func (c *clientCredentialsStrategy) Apply(ctx context.Context, req *http.Request) error {
	var tokenInfo *oauth2.TokenEndpointResponse
	var err error

	// ensure the token has still 15 seconds lifetime
	c.mutex.RLock()
	if c.lastResponse != nil && c.lastResponse.ExpiresIn+15 < time.Now().Unix() {
		tokenInfo = c.lastResponse
		c.mutex.RUnlock()
	} else {
		c.mutex.RUnlock()

		tokenInfo, err = c.getAccessToken(ctx)
		if err != nil {
			return err
		}
		// set absolute expiration time
		tokenInfo.ExpiresIn += time.Now().Unix()

		c.mutex.Lock()
		c.lastResponse = tokenInfo
		c.mutex.Unlock()
	}

	req.Header.Set("Authorization", tokenInfo.TokenType+" "+tokenInfo.AccessToken)
	return nil
}

func (c *clientCredentialsStrategy) getAccessToken(ctx context.Context) (*oauth2.TokenEndpointResponse, error) {
	client := httpretry.NewCustomClient(
		&http.Client{
			Transport: &httpx.TracingRoundTripper{Next: http.DefaultTransport},
		},
		httpretry.WithBackoffPolicy(httpretry.ExponentialBackoff(100*time.Millisecond, 3*time.Second, 0)))

	// create payload body
	data := url.Values{
		"grant_type": []string{"client_credentials"},
	}
	if len(c.scopes) != 0 {
		data.Add("scope", strings.Join(c.scopes, " "))
	}
	content := data.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenUrl, strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(url.QueryEscape(c.clientId), url.QueryEscape(c.clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return c.readResponse(resp)
}

func (*clientCredentialsStrategy) readResponse(resp *http.Response) (*oauth2.TokenEndpointResponse, error) {
	var r oauth2.TokenEndpointResponse
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		if err := json.Unmarshal(rawData, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
	} else {
		return nil, errors.New(fmt.Sprintf("unexpected response. code: %v", resp.StatusCode))
	}
	return &r, nil
}
