package endpoint

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type ClientCredentialsStrategy struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"scopes"`
	TokenURL     string   `mapstructure:"token_url"`

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
	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}

	content := data.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(content))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return readResponse(resp)
}

func readResponse(resp *http.Response) (*tokenEndpointResponse, error) {
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		var ter tokenEndpointResponse
		if err := json.Unmarshal(rawData, &ter); err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
				CausedBy(err)
		}

		return &ter, nil
	}

	return nil, errorchain.
		NewWithMessagef(heimdall.ErrInternal, "unexpected response. code: %v", resp.StatusCode)
}
