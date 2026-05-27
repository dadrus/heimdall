// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/inhies/go-bytesize"
	"github.com/redis/rueidis"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/tlsx"
)

// for test purposes only.
var rootCertPool *x509.CertPool //nolint:gochecknoglobals

type redisCredentials struct {
	Username string `json:"username"`
	Password string `json:"password" validate:"required"`
}

type clientCache struct {
	Disabled          bool              `mapstructure:"disabled"`
	TTL               time.Duration     `mapstructure:"ttl"`
	SizePerConnection bytesize.ByteSize `mapstructure:"size_per_connection"`
}

type tlsConfig struct {
	config.TLS `mapstructure:",squash"`

	Disabled bool `mapstructure:"disabled" validate:"enforced=false"`
}

type baseConfig struct {
	Credentials   *config.Secret     `mapstructure:"credentials"`
	ClientCache   clientCache        `mapstructure:"client_cache"`
	BufferLimit   config.BufferLimit `mapstructure:"buffer_limit"`
	Timeout       config.Timeout     `mapstructure:"timeout"`
	MaxFlushDelay time.Duration      `mapstructure:"max_flush_delay"`
	TLS           tlsConfig          `mapstructure:"tls"`
}

func (c baseConfig) clientOptions(app app.Context) (rueidis.ClientOption, error) {
	tlsCfg, err := c.tlsConfig(app)
	if err != nil {
		return rueidis.ClientOption{}, err
	}

	informer, err := c.credentialsInformer(app)
	if err != nil {
		return rueidis.ClientOption{}, err
	}

	return rueidis.ClientOption{
		ClientName:          "heimdall",
		DisableCache:        c.ClientCache.Disabled,
		CacheSizeEachConn:   safecast.MustConvert[int](uint64(c.ClientCache.SizePerConnection)),
		WriteBufferEachConn: safecast.MustConvert[int](uint64(c.BufferLimit.Write)),
		ReadBufferEachConn:  safecast.MustConvert[int](uint64(c.BufferLimit.Read)),
		ConnWriteTimeout:    c.Timeout.Write,
		MaxFlushDelay:       c.MaxFlushDelay,
		AuthCredentialsFn:   authCredentials(informer),
		DialCtxFn:           dialCtx(tlsCfg),
	}, nil
}

func (c baseConfig) tlsConfig(appCtx app.Context) (*tls.Config, error) {
	if c.TLS.Disabled {
		return nil, nil //nolint:nilnil
	}

	tlsCfg, err := tlsx.ToClientTLSConfig(
		context.Background(),
		appCtx.SecretResolver(),
		&c.TLS.TLS,
		appCtx.KeyRegistry(),
	)
	if err != nil {
		return nil, err
	}

	tlsCfg.RootCAs = rootCertPool

	return tlsCfg, nil
}

func (c baseConfig) credentialsInformer(
	appCtx app.Context,
) (*secrets.CredentialsInformer[rueidis.AuthCredentials], error) {
	if c.Credentials == nil {
		return nil, nil //nolint:nilnil
	}

	informer, err := secrets.NewCredentialsInformer(
		context.Background(),
		appCtx.SecretResolver(),
		secrets.Reference{Source: c.Credentials.Source, Selector: c.Credentials.Selector},
		secrets.WithConverter(toRedisCredentials(appCtx.DecoderFactory())),
	)
	if err != nil {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"failed resolving redis credentials",
		).CausedBy(err)
	}

	return informer, nil
}

func toRedisCredentials(df encoding.DecoderFactory) func(creds secrets.Credentials) (rueidis.AuthCredentials, error) {
	return func(creds secrets.Credentials) (rueidis.AuthCredentials, error) {
		var data redisCredentials

		if err := df.Decoder().DecodeMap(&data, creds.Values()); err != nil {
			return rueidis.AuthCredentials{}, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"failed decoding redis credentials",
			).CausedBy(err)
		}

		return rueidis.AuthCredentials{
			Username: data.Username,
			Password: data.Password,
		}, nil
	}
}

func authCredentials(
	cr *secrets.CredentialsInformer[rueidis.AuthCredentials],
) func(credentialsContext rueidis.AuthCredentialsContext) (rueidis.AuthCredentials, error) {
	return func(_ rueidis.AuthCredentialsContext) (rueidis.AuthCredentials, error) {
		if cr == nil {
			return rueidis.AuthCredentials{}, nil
		}

		creds, ok := cr.Get()
		if !ok {
			return rueidis.AuthCredentials{}, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"redis credentials are not available",
			)
		}

		return creds, nil
	}
}

func dialCtx(tlsCfg *tls.Config) func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
	type Dialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}

	return func(ctx context.Context, addr string, dialer *net.Dialer, _ *tls.Config) (net.Conn, error) {
		var cd Dialer = dialer

		if tlsCfg != nil {
			cd = &tls.Dialer{
				NetDialer: dialer,
				Config:    tlsCfg,
			}
		}

		return cd.DialContext(ctx, "tcp", addr)
	}
}
