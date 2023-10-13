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

type ClientCredentialsStrategy struct {
	TokenURL     string   `mapstructure:"token_url"     validate:"required,url"`
	ClientID     string   `mapstructure:"client_id"     validate:"required"`
	ClientSecret string   `mapstructure:"client_secret" validate:"required"`
	Scopes       []string `mapstructure:"scopes"`
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
	digest.Write(stringx.ToBytes(c.ClientID))
	digest.Write(stringx.ToBytes(c.ClientSecret))
	digest.Write(stringx.ToBytes(c.TokenURL))
	digest.Write(stringx.ToBytes(strings.Join(c.Scopes, "")))

	return hex.EncodeToString(digest.Sum(nil))
}

func (c *ClientCredentialsStrategy) getAccessToken(ctx context.Context) (*tokenEndpointResponse, error) {
	ept := endpoint.Endpoint{
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

	hash.Write(stringx.ToBytes(c.ClientID))
	hash.Write(stringx.ToBytes(c.ClientSecret))

	return hash.Sum(nil)
}
