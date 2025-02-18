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

package finalizers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	defaultJWTTTL      = 5 * time.Minute
	defaultCacheLeeway = 5 * time.Second
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(app app.Context, id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerJwt {
				return false, nil, nil
			}

			finalizer, err := newJWTFinalizer(app, id, conf)

			return true, finalizer, err
		})
}

type jwtFinalizer struct {
	id           string
	app          app.Context
	claims       template.Template
	ttl          time.Duration
	headerName   string
	headerScheme string
	signer       *jwtSigner
	v            values.Values
}

func newJWTFinalizer(app app.Context, id string, rawConfig map[string]any) (*jwtFinalizer, error) {
	logger := app.Logger()
	logger.Info().Str("_id", id).Msg("Creating jwt finalizer")

	type HeaderConfig struct {
		Name   string `mapstructure:"name"   validate:"required"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		Signer SignerConfig      `mapstructure:"signer" validate:"required"`
		TTL    *time.Duration    `mapstructure:"ttl"    validate:"omitempty,gt=1s"`
		Claims template.Template `mapstructure:"claims"`
		Values values.Values     `mapstructure:"values"`
		Header *HeaderConfig     `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for jwt finalizer '%s'", id).CausedBy(err)
	}

	signer, err := newJWTSigner(&conf.Signer, app.Watcher())
	if err != nil {
		return nil, err
	}

	app.KeyHolderRegistry().AddKeyHolder(signer)

	fin := &jwtFinalizer{
		id:     id,
		app:    app,
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
		signer: signer,
		v:      conf.Values,
	}

	app.CertificateObserver().Add(fin)

	return fin, nil
}

func (f *jwtFinalizer) Execute(ctx heimdall.RequestContext, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Str("_id", f.id).Msg("Finalizing using JWT finalizer")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute jwt finalizer due to 'nil' subject").
			WithErrorContext(f)
	}

	cch := cache.Ctx(ctx.Context())

	var (
		jwtToken string
		err      error
	)

	cacheKey := f.calculateCacheKey(ctx, sub)
	if entry, err := cch.Get(ctx.Context(), cacheKey); err == nil {
		logger.Debug().Msg("Reusing JWT from cache")

		jwtToken = stringx.ToString(entry)
	}

	if len(jwtToken) == 0 {
		jwtToken, err = f.generateToken(ctx, sub)
		if err != nil {
			return err
		}

		if len(cacheKey) != 0 && f.ttl > defaultCacheLeeway {
			if err = cch.Set(ctx.Context(), cacheKey, stringx.ToBytes(jwtToken), f.ttl-defaultCacheLeeway); err != nil {
				logger.Warn().Err(err).Msg("Failed to cache JWT token")
			}
		}
	}

	ctx.AddHeaderForUpstream(f.headerName, fmt.Sprintf("%s %s", f.headerScheme, jwtToken))

	return nil
}

func (f *jwtFinalizer) WithConfig(rawConfig map[string]any) (Finalizer, error) {
	if len(rawConfig) == 0 {
		return f, nil
	}

	type Config struct {
		TTL    *time.Duration    `mapstructure:"ttl"    validate:"omitempty,gt=1s"`
		Claims template.Template `mapstructure:"claims"`
		Values values.Values     `mapstructure:"values"`
	}

	var conf Config
	if err := decodeConfig(f.app.Validator(), rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for jwt finalizer '%s'", f.id).CausedBy(err)
	}

	return &jwtFinalizer{
		id:     f.id,
		app:    f.app,
		claims: x.IfThenElse(conf.Claims != nil, conf.Claims, f.claims),
		ttl: x.IfThenElseExec(conf.TTL != nil,
			func() time.Duration { return *conf.TTL },
			func() time.Duration { return f.ttl }),
		headerName:   f.headerName,
		headerScheme: f.headerScheme,
		signer:       f.signer,
		v:            f.v.Merge(conf.Values),
	}, nil
}

func (f *jwtFinalizer) ID() string { return f.id }

func (f *jwtFinalizer) ContinueOnError() bool { return false }

func (f *jwtFinalizer) generateToken(ctx heimdall.RequestContext, sub *subject.Subject) (string, error) {
	logger := zerolog.Ctx(ctx.Context())
	logger.Debug().Msg("Generating new JWT")

	result := map[string]any{}

	if f.claims != nil {
		vals, err := f.v.Render(map[string]any{
			"Subject": sub,
			"Outputs": ctx.Outputs(),
		})
		if err != nil {
			return "", errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to render values").
				WithErrorContext(f).
				CausedBy(err)
		}

		claims, err := f.claims.Render(map[string]any{
			"Subject": sub,
			"Outputs": ctx.Outputs(),
			"Values":  vals,
		})
		if err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render claims").
				WithErrorContext(f).
				CausedBy(err)
		}

		logger.Debug().Str("_value", claims).Msg("Rendered template")

		if err = json.Unmarshal(stringx.ToBytes(claims), &result); err != nil {
			return "", errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal claims rendered by template").
				WithErrorContext(f).
				CausedBy(err)
		}
	}

	token, err := f.signer.Sign(sub.ID, f.ttl, result)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to sign token").
			WithErrorContext(f).
			CausedBy(err)
	}

	return token, nil
}

func (f *jwtFinalizer) calculateCacheKey(ctx heimdall.RequestContext, sub *subject.Subject) string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)

	//nolint:gosec
	// no integer overflow during conversion possible
	binary.LittleEndian.PutUint64(ttlBytes, uint64(f.ttl))

	hash := sha256.New()
	hash.Write(f.signer.Hash())
	hash.Write(x.IfThenElseExec(f.claims != nil,
		func() []byte { return f.claims.Hash() },
		func() []byte { return []byte{} }))
	hash.Write(ttlBytes)
	hash.Write(sub.Hash())

	for key, val := range f.v {
		hash.Write(stringx.ToBytes(key))
		hash.Write(val.Hash())
	}

	rawSub, _ := json.Marshal(ctx.Outputs())
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil))
}

func (f *jwtFinalizer) Name() string                      { return f.id }
func (f *jwtFinalizer) Certificates() []*x509.Certificate { return f.signer.activeCertificateChain() }
