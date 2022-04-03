package endpoint

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ClientCredentialsStrategy struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"scopes"`
	TokenURL     string   `mapstructure:"token_url"`
}

func (c *ClientCredentialsStrategy) Apply(ctx context.Context, req *http.Request) error {
	cch := cache.Ctx(ctx)
	if cch != nil {
		item := cch.Get("foo")
		if item != nil {
			tokenInfo := item.(*tokenEndpointResponse)
			req.Header.Set("Authorization", tokenInfo.TokenType+" "+tokenInfo.AccessToken)

			return nil
		}
	}

	resp, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}

	if cch != nil {
		cch.Set("foo", resp, time.Duration(resp.ExpiresIn-15)*time.Second)
	}

	req.Header.Set("Authorization", resp.TokenType+" "+resp.AccessToken)

	return nil
}

func (c *ClientCredentialsStrategy) getAccessToken(ctx context.Context) (*tokenEndpointResponse, error) {
	ept := Endpoint{
		URL:    c.TokenURL,
		Method: http.MethodPost,
		AuthStrategy: &BasicAuthStrategy{
			User:     url.QueryEscape(c.ClientID),
			Password: url.QueryEscape(c.ClientSecret),
		},
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept-Type":  "application/json",
		},
	}

	// create payload body
	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}

	req, err := ept.CreateRequest(ctx, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := ept.CreateClient().Do(req)
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
