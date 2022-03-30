package endpoint

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

	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

type ClientCredentialsStrategy struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	TokenUrl     string   `json:"token_url"`

	lastResponse *tokenEndpointResponse
	mutex        sync.RWMutex
}

func (c *ClientCredentialsStrategy) Apply(ctx context.Context, req *http.Request) error {
	var tokenInfo tokenEndpointResponse

	// ensure the token has still 15 seconds lifetime
	c.mutex.RLock()
	if c.lastResponse != nil && c.lastResponse.ExpiresIn+15 < time.Now().Unix() {
		tokenInfo = *c.lastResponse
		c.mutex.RUnlock()
	} else {
		c.mutex.RUnlock()

		resp, err := c.getAccessToken(ctx)
		if err != nil {
			return err
		}
		// set absolute expiration time
		tokenInfo = *resp
		tokenInfo.ExpiresIn += time.Now().Unix()

		c.mutex.Lock()
		c.lastResponse = &tokenInfo
		c.mutex.Unlock()
	}

	req.Header.Set("Authorization", tokenInfo.TokenType+" "+tokenInfo.AccessToken)
	return nil
}

func (c *ClientCredentialsStrategy) getAccessToken(ctx context.Context) (*tokenEndpointResponse, error) {
	client := httpretry.NewCustomClient(
		&http.Client{
			Transport: &httpx.TracingRoundTripper{Next: http.DefaultTransport},
		},
		httpretry.WithBackoffPolicy(httpretry.ExponentialBackoff(100*time.Millisecond, 3*time.Second, 0)))

	// create payload body
	data := url.Values{
		"grant_type": []string{"client_credentials"},
	}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}
	content := data.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenUrl, strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(url.QueryEscape(c.ClientId), url.QueryEscape(c.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return readResponse(resp)
}

func readResponse(resp *http.Response) (*tokenEndpointResponse, error) {
	var r tokenEndpointResponse
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
