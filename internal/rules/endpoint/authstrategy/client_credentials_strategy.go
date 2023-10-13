// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package authstrategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type AuthMethod string

const (
	authMethodBasicAuth   AuthMethod = "basic_auth"
	authMethodRequestBody AuthMethod = "request_body"
)

type HeaderConfig struct {
	Name   string `mapstructure:"name"   validate:"required"`
	Scheme string `mapstructure:"scheme"`
}

type ClientCredentialsStrategy struct {
	TokenURL     string         `mapstructure:"token_url"     validate:"required,url"`
	ClientID     string         `mapstructure:"client_id"     validate:"required"`
	ClientSecret string         `mapstructure:"client_secret" validate:"required"`
	AuthMethod   AuthMethod     `mapstructure:"auth_method"   validate:"omitempty,oneof=basic_auth request_body"`
	Scopes       []string       `mapstructure:"scopes"`
	TTL          *time.Duration `mapstructure:"cache_ttl"`
	Header       *HeaderConfig  `mapstructure:"header"`
}

func (c *ClientCredentialsStrategy) Apply(ctx context.Context, req *http.Request) error {
	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Applying client-credentials strategy to authenticate request")

	cch := cache.Ctx(ctx)

	var (
		ok         bool
		cacheKey   string
		cacheEntry any
		token      string
	)

	if c.isCacheEnabled() {
		cacheKey = c.calculateCacheKey()
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if token, ok = cacheEntry.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing access token from cache")
		}
	}

	if len(token) == 0 {
		logger.Debug().Msg("Retrieving new access token")

		tokenInfo, err := c.getAccessToken(ctx)
		if err != nil {
			return err
		}

		token = tokenInfo.AccessToken

		if cacheTTL := c.getCacheTTL(tokenInfo); cacheTTL > 0 {
			cch.Set(cacheKey, token, cacheTTL)
		}
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func (c *ClientCredentialsStrategy) calculateCacheKey() string { return hex.EncodeToString(c.Hash()) }

func (c *ClientCredentialsStrategy) getAccessToken(ctx context.Context) (*TokenSuccessfulResponse, error) {
	ept := endpoint.Endpoint{
		URL:          c.TokenURL,
		Method:       http.MethodPost,
		AuthStrategy: c.authStrategy(),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept-Type":  "application/json",
		},
	}

	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}

	// This is not recommended, but there are non-compliant servers out there
	// which do not support the Basic Auth authentication method required by
	// the spec. See also https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	if ept.AuthStrategy == nil {
		data.Add("client_id", c.ClientID)
		data.Add("client_secret", c.ClientSecret)
	}

	rawData, err := ept.SendRequest(
		ctx,
		strings.NewReader(data.Encode()),
		nil,
		func(resp *http.Response) ([]byte, error) {
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
				return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
					"unexpected response code: %v", resp.StatusCode)
			}

			rawData, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to read response").CausedBy(err)
			}

			if resp.StatusCode == http.StatusBadRequest {
				var ter TokenErrorResponse
				if err := json.Unmarshal(rawData, &ter); err != nil {
					return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
						"failed to unmarshal response").CausedBy(err)
				}

				return nil, errorchain.New(heimdall.ErrCommunication).CausedBy(&ter)
			}

			return rawData, nil
		},
	)
	if err != nil {
		return nil, err
	}

	var resp TokenEndpointResponse
	if err := json.Unmarshal(rawData, &resp); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			CausedBy(err)
	}

	if resp.Error() != nil {
		return nil, errorchain.New(heimdall.ErrCommunication).CausedBy(resp.Error())
	}

	return resp.TokenSuccessfulResponse, nil
}

func (c *ClientCredentialsStrategy) authStrategy() endpoint.AuthenticationStrategy {
	if c.AuthMethod == authMethodRequestBody {
		return nil
	}

	return &BasicAuthStrategy{
		User:     url.QueryEscape(c.ClientID),
		Password: url.QueryEscape(c.ClientSecret),
	}
}

func (c *ClientCredentialsStrategy) getCacheTTL(resp *TokenSuccessfulResponse) time.Duration {
	// timeLeeway defines the default time deviation to ensure the token is still valid
	// when used from cache
	const timeLeeway = 5

	if !c.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the token endpoint response (if available)
	// or if ttl has been configured. Latter overwrites the settings in the token endpoint response
	// if it is shorter than the ttl in the token endpoint response
	tokenEndpointResponseTTL := x.IfThenElseExec(resp.ExpiresIn != 0,
		func() time.Duration {
			expiresIn := resp.ExpiresIn - timeLeeway

			return x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)
		},
		func() time.Duration { return 0 })

	configuredTTL := x.IfThenElseExec(c.TTL != nil,
		func() time.Duration { return *c.TTL },
		func() time.Duration { return 0 })

	switch {
	case configuredTTL == 0 && tokenEndpointResponseTTL == 0:
		return 0
	case configuredTTL == 0 && tokenEndpointResponseTTL != 0:
		return tokenEndpointResponseTTL
	case configuredTTL != 0 && tokenEndpointResponseTTL == 0:
		return configuredTTL
	default:
		return min(configuredTTL, tokenEndpointResponseTTL)
	}
}

func (c *ClientCredentialsStrategy) isCacheEnabled() bool {
	// cache is enabled if it is not configured (in that case the ttl value from the
	// token response if used), or if it is configured and the value > 0
	return c.TTL == nil || (c.TTL != nil && *c.TTL > 0)
}

func (c *ClientCredentialsStrategy) Hash() []byte {
	digest := sha256.New()
	digest.Write(stringx.ToBytes(c.ClientID))
	digest.Write(stringx.ToBytes(c.ClientSecret))
	digest.Write(stringx.ToBytes(c.TokenURL))
	digest.Write(stringx.ToBytes(strings.Join(c.Scopes, "")))

	return digest.Sum(nil)
}
