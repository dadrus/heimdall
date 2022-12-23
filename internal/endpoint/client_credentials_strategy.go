package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const defaultCacheLeeway = 15

type ClientCredentialsStrategy struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"scopes"`
	TokenURL     string   `mapstructure:"token_url"`
}

func (c *ClientCredentialsStrategy) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying client-credentials strategy to authenticate request")

	key := c.calculateCacheKey()

	cch := cache.Ctx(ctx)
	if item := cch.Get(key); item != nil {
		logger.Debug().Msg("Reusing access token from cache")

		if tokenInfo, ok := item.(*tokenEndpointResponse); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(key)
		} else {
			req.Header.Set("Authorization", tokenInfo.TokenType+" "+tokenInfo.AccessToken)

			return nil
		}
	}

	logger.Debug().Msg("Retrieving new access token")

	resp, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}

	cch.Set(key, resp, time.Duration(resp.ExpiresIn-defaultCacheLeeway)*time.Second)

	req.Header.Set("Authorization", resp.TokenType+" "+resp.AccessToken)

	return nil
}

func (c *ClientCredentialsStrategy) calculateCacheKey() string {
	digest := sha256.New()
	digest.Write([]byte(c.ClientID))
	digest.Write([]byte(c.ClientSecret))
	digest.Write([]byte(c.TokenURL))
	digest.Write([]byte(strings.Join(c.Scopes, "")))

	return hex.EncodeToString(digest.Sum(nil))
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

	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}

	rawData, err := ept.SendRequest(ctx, strings.NewReader(data.Encode()), nil)
	if err != nil {
		return nil, err
	}

	var ter tokenEndpointResponse
	if err := json.Unmarshal(rawData, &ter); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			CausedBy(err)
	}

	return &ter, nil
}

func (c *ClientCredentialsStrategy) Hash() []byte {
	hash := sha256.New()

	hash.Write([]byte(c.ClientID))
	hash.Write([]byte(c.ClientSecret))

	return hash.Sum(nil)
}
