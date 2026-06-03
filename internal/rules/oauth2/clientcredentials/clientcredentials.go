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

package clientcredentials

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
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type AuthMethod string

const (
	AuthMethodBasicAuth   AuthMethod = "basic_auth"
	AuthMethodRequestBody AuthMethod = "request_body"
)

type clientCredentialsAuthStrategy struct {
	ClientID     string
	ClientSecret string
	AuthMethod   AuthMethod
}

func (a clientCredentialsAuthStrategy) Apply(req *http.Request) error {
	if a.AuthMethod == AuthMethodRequestBody {
		// This is not recommended, but there are non-compliant servers out there
		// which do support the Basic Auth authentication method required by
		// the spec. See also https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
		data, _ := io.ReadAll(req.Body)
		values, _ := url.ParseQuery(stringx.ToString(data))

		values.Add("client_id", a.ClientID)
		values.Add("client_secret", a.ClientSecret)

		body := strings.NewReader(values.Encode())
		req.Body = io.NopCloser(body)
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(body), nil }
		req.ContentLength = int64(body.Len())
	} else {
		req.SetBasicAuth(url.QueryEscape(a.ClientID), url.QueryEscape(a.ClientSecret))
	}

	return nil
}

func (a clientCredentialsAuthStrategy) Hash() []byte {
	digest := sha256.New()
	digest.Write(stringx.ToBytes(a.ClientID))
	digest.Write(stringx.ToBytes(a.ClientSecret))
	digest.Write(stringx.ToBytes(string(a.AuthMethod)))

	var result [sha256.Size]byte

	return digest.Sum(result[:0])
}

type Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	AuthMethod   AuthMethod
	Scopes       []string
	TTL          *time.Duration
}

func (c Config) Token(ctx context.Context) (*TokenInfo, error) {
	logger := zerolog.Ctx(ctx)
	cch := cache.Ctx(ctx)

	var cacheKey string

	if c.isCacheEnabled() {
		cacheKey = c.calculateCacheKey()
		if entry, err := cch.Get(ctx, cacheKey); err == nil {
			var tokenInfo TokenInfo

			if err = json.Unmarshal(entry, &tokenInfo); err == nil {
				logger.Debug().Msg("Reusing access token from cache")

				return &tokenInfo, nil
			}
		}
	}

	logger.Debug().Msg("Requesting new access token")

	tokenInfo, err := c.fetchToken(ctx)
	if err != nil {
		return nil, err
	}

	if cacheTTL := c.getCacheTTL(tokenInfo); cacheTTL > 0 {
		data, _ := json.Marshal(tokenInfo)

		if err = cch.Set(ctx, cacheKey, data, cacheTTL); err != nil {
			logger.Warn().Err(err).Msg("Failed to cache token info")
		}
	}

	return tokenInfo, nil
}

func (c Config) Hash() []byte {
	digest := sha256.New()
	digest.Write(stringx.ToBytes(c.ClientID))
	digest.Write(stringx.ToBytes(c.ClientSecret))
	digest.Write(stringx.ToBytes(c.TokenURL))
	digest.Write(stringx.ToBytes(string(c.AuthMethod)))
	digest.Write(stringx.ToBytes(strings.Join(c.Scopes, "")))

	var result [sha256.Size]byte

	return digest.Sum(result[:0])
}

func (c Config) calculateCacheKey() string {
	return hex.EncodeToString(c.Hash())
}

func (c Config) getCacheTTL(resp *TokenInfo) time.Duration {
	// timeLeeway defines the default time deviation to ensure the token is still valid
	// when used from cache
	const timeLeeway = 5

	if !c.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the token endpoint response (if available)
	// or if ttl has been configured. Latter overwrites the settings in the token endpoint response
	// if it is shorter than the ttl in the token endpoint response
	tokenEndpointResponseTTL := x.IfThenElseExec(!resp.Expiry.IsZero(),
		func() time.Duration {
			expiresIn := time.Until(resp.Expiry) - timeLeeway*time.Second

			return x.IfThenElse(expiresIn > 0, expiresIn, 0)
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

func (c Config) isCacheEnabled() bool {
	// cache is enabled if it is not configured (in that case the ttl value from the
	// token response if used), or if it is configured and the value > 0
	return c.TTL == nil || (c.TTL != nil && *c.TTL > 0)
}

func (c Config) fetchToken(ctx context.Context) (*TokenInfo, error) {
	ept, _ := endpoint.New(c.TokenURL,
		endpoint.WithMethod(http.MethodPost),
		endpoint.WithAuthStrategy(clientCredentialsAuthStrategy{
			AuthMethod:   c.AuthMethod,
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
		}),
		endpoint.WithHeader("Content-Type", "application/x-www-form-urlencoded"),
		endpoint.WithHeader("Accept", "application/json"),
	)

	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(c.Scopes) != 0 {
		data.Add("scope", strings.Join(c.Scopes, " "))
	}

	rawData, err := ept.SendRequest(
		ctx,
		strings.NewReader(data.Encode()),
		nil,
		func(resp *http.Response) ([]byte, error) {
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
				return nil, errorchain.NewWithMessagef(pipeline.ErrCommunication,
					"unexpected response code: %v", resp.StatusCode)
			}

			rawData, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
					"failed to read response").CausedBy(err)
			}

			if resp.StatusCode == http.StatusBadRequest {
				var ter TokenErrorResponse
				if err = json.Unmarshal(rawData, &ter); err != nil {
					return nil, errorchain.NewWithMessagef(pipeline.ErrCommunication,
						"failed to fetch token: %s", stringx.ToString(rawData))
				}

				return nil, errorchain.New(pipeline.ErrCommunication).CausedBy(&ter)
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
			NewWithMessage(pipeline.ErrInternal, "failed to unmarshal response").
			CausedBy(err)
	}

	tokenInfo, err := resp.TokenInfo()
	if err != nil {
		return nil, errorchain.New(pipeline.ErrCommunication).CausedBy(err)
	}

	return tokenInfo, nil
}
