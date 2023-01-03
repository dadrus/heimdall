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
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
	id     string
	claims template.Template
	ttl    time.Duration
}

func newJWTUnifier(id string, rawConfig map[string]any) (*jwtUnifier, error) {
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

	if conf.TTL != nil && *conf.TTL <= 1*time.Second {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "configured JWT ttl is less than one second")
	}

	return &jwtUnifier{
		id:     id,
		claims: conf.Claims,
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return defaultJWTTTL }),
	}, nil
}

func (m *jwtUnifier) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Unifying using JWT unifier")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute jwt unifier due to 'nil' subject").
			WithErrorContext(m)
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheEntry any
		jwtToken   string
		ok         bool
		err        error
	)

	cacheKey := m.calculateCacheKey(sub, ctx.Signer())
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

		jwtToken, err = m.generateToken(ctx, sub)
		if err != nil {
			return err
		}

		if len(cacheKey) != 0 && m.ttl > defaultCacheLeeway {
			cch.Set(cacheKey, jwtToken, m.ttl-defaultCacheLeeway)
		}
	}

	ctx.AddHeaderForUpstream("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	return nil
}

func (m *jwtUnifier) WithConfig(rawConfig map[string]any) (Unifier, error) {
	if len(rawConfig) == 0 {
		return m, nil
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
		id:     m.id,
		claims: x.IfThenElse(conf.Claims != nil, conf.Claims, m.claims),
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return m.ttl }),
	}, nil
}

func (m *jwtUnifier) HandlerID() string {
	return m.id
}

func (m *jwtUnifier) generateToken(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	iss := ctx.Signer()

	claims := map[string]any{}
	if m.claims != nil {
		vals, err := m.claims.Render(nil, sub)
		if err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render claims").
				WithErrorContext(m).
				CausedBy(err)
		}

		if err = json.Unmarshal([]byte(vals), &claims); err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal claims rendered by template").
				WithErrorContext(m).
				CausedBy(err)
		}
	}

	token, err := iss.Sign(sub.ID, m.ttl, claims)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to sign token").
			WithErrorContext(m).
			CausedBy(err)
	}

	return token, nil
}

func (m *jwtUnifier) calculateCacheKey(sub *subject.Subject, iss heimdall.JWTSigner) string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(m.ttl))

	hash := sha256.New()
	hash.Write(iss.Hash())
	hash.Write(x.IfThenElseExec(m.claims != nil,
		func() []byte { return m.claims.Hash() },
		func() []byte { return []byte("nil") }))
	hash.Write(ttlBytes)
	hash.Write(sub.Hash())

	return hex.EncodeToString(hash.Sum(nil))
}
