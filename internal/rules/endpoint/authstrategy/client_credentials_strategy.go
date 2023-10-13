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
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const defaultCacheLeeway = 15

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

	key := c.calculateCacheKey()

	cch := cache.Ctx(ctx)
	if item := cch.Get(key); item != nil {
		logger.Debug().Msg("Reusing access token from cache")

		if tokenInfo, ok := item.(*TokenSuccessfulResponse); !ok {
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
	digest.Write(stringx.ToBytes(c.ClientID))
	digest.Write(stringx.ToBytes(c.ClientSecret))
	digest.Write(stringx.ToBytes(c.TokenURL))
	digest.Write(stringx.ToBytes(strings.Join(c.Scopes, "")))

	return hex.EncodeToString(digest.Sum(nil))
}

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

func (c *ClientCredentialsStrategy) Hash() []byte {
	hash := sha256.New()

	hash.Write(stringx.ToBytes(c.ClientID))
	hash.Write(stringx.ToBytes(c.ClientSecret))

	return hash.Sum(nil)
}
