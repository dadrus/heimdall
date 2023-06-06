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

package unifiers

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	defaultJWTTTL      = 5 * time.Minute
	defaultCacheLeeway = 5 * time.Second
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerUnifierTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Unifier, error) {
			if typ != UnifierJwt {
				return false, nil, nil
			}

			unifier, err := newJWTUnifier(id, conf)

			return true, unifier, err
		})
}

type jwtUnifier struct {
	id           string
	claims       template.Template
	ttl          time.Duration
	headerName   string
	headerScheme string
}

func newJWTUnifier(id string, rawConfig map[string]any) (*jwtUnifier, error) {
	type HeaderConfig struct {
		Name   string `mapstructure:"name"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		Claims template.Template `mapstructure:"claims"`
		TTL    *time.Duration    `mapstructure:"ttl"`
		Header *HeaderConfig     `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT unifier config").
			CausedBy(err)
	}

	if conf.TTL != nil && *conf.TTL <= 1*time.Second {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "configured JWT ttl is less than one second")
	}

	if conf.Header != nil && len(strings.TrimSpace(conf.Header.Name)) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "configured JWT header name is an empty string")
	}

	return &jwtUnifier{
		id:     id,
		claims: conf.Claims,
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return defaultJWTTTL }),
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return "Authorization" }),
		headerScheme: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return "Bearer" }),
	}, nil
}

func (u *jwtUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Str("_id", u.id).Msg("Unifying using JWT unifier")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute jwt unifier due to 'nil' subject").
			WithErrorContext(u)
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheEntry any
		jwtToken   string
		ok         bool
		err        error
	)

	cacheKey := u.calculateCacheKey(sub, ctx.Signer())
	cacheEntry = cch.Get(cacheKey)

	if cacheEntry != nil {
		if jwtToken, ok = cacheEntry.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing JWT from cache")
		}
	}

	if len(jwtToken) == 0 {
		logger.Debug().Msg("Generating new JWT")

		jwtToken, err = u.generateToken(ctx, sub)
		if err != nil {
			return err
		}

		if len(cacheKey) != 0 && u.ttl > defaultCacheLeeway {
			cch.Set(cacheKey, jwtToken, u.ttl-defaultCacheLeeway)
		}
	}

	ctx.AddHeaderForUpstream(u.headerName, fmt.Sprintf("%s %s", u.headerScheme, jwtToken))

	return nil
}

func (u *jwtUnifier) WithConfig(rawConfig map[string]any) (Unifier, error) {
	if len(rawConfig) == 0 {
		return u, nil
	}

	type Config struct {
		Claims template.Template `mapstructure:"claims"`
		TTL    *time.Duration    `mapstructure:"ttl"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT unifier config").
			CausedBy(err)
	}

	if conf.TTL != nil && *conf.TTL < 1*time.Second {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "configured JWT ttl is less than one second")
	}

	return &jwtUnifier{
		id:     u.id,
		claims: x.IfThenElse(conf.Claims != nil, conf.Claims, u.claims),
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return u.ttl }),
	}, nil
}

func (u *jwtUnifier) HandlerID() string { return u.id }

func (u *jwtUnifier) ContinueOnError() bool { return false }

func (u *jwtUnifier) generateToken(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	iss := ctx.Signer()

	claims := map[string]any{}
	if u.claims != nil {
		vals, err := u.claims.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
		})
		if err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render claims").
				WithErrorContext(u).
				CausedBy(err)
		}

		if err = json.Unmarshal(stringx.ToBytes(vals), &claims); err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal claims rendered by template").
				WithErrorContext(u).
				CausedBy(err)
		}
	}

	token, err := iss.Sign(sub.ID, u.ttl, claims)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to sign token").
			WithErrorContext(u).
			CausedBy(err)
	}

	return token, nil
}

func (u *jwtUnifier) calculateCacheKey(sub *subject.Subject, iss heimdall.JWTSigner) string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(u.ttl))

	hash := sha256.New()
	hash.Write(iss.Hash())
	hash.Write(x.IfThenElseExec(u.claims != nil,
		func() []byte { return u.claims.Hash() },
		func() []byte { return []byte{} }))
	hash.Write(ttlBytes)
	hash.Write(sub.Hash())

	return hex.EncodeToString(hash.Sum(nil))
}
