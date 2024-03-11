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
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/redis/rueidis"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/tlsx"
)

// for test purposes only.
var rootCertPool *x509.CertPool //nolint:gochecknoglobals

type clientCache struct {
	Disabled          bool              `mapstructure:"disabled"`
	TTL               time.Duration     `mapstructure:"ttl"`
	SizePerConnection bytesize.ByteSize `mapstructure:"size_per_connection"`
}

type credentials interface {
	register(cw watcher.Watcher) error
	get() rueidis.AuthCredentials
}

type staticCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (c *staticCredentials) register(_ watcher.Watcher) error { return nil }

func (c *staticCredentials) get() rueidis.AuthCredentials {
	return rueidis.AuthCredentials{
		Username: c.Username,
		Password: c.Password,
	}
}

type fileCredentials struct {
	Path string

	creds *staticCredentials
	mut   sync.Mutex
}

func (c *fileCredentials) load() error {
	cf, err := os.Open(c.Path)
	if err != nil {
		return err
	}

	var creds staticCredentials

	dec := yaml.NewDecoder(cf)
	dec.KnownFields(true)

	if err = dec.Decode(&creds); err != nil {
		return err
	}

	c.mut.Lock()
	c.creds = &creds
	c.mut.Unlock()

	return nil
}

func (c *fileCredentials) OnChanged(log zerolog.Logger) {
	if err := c.load(); err != nil {
		log.Warn().Err(err).
			Str("_source", "redis-cache").
			Str("_file", c.Path).
			Msg("Config reload failed")
	} else {
		log.Info().
			Str("_source", "redis-cache").
			Str("_file", c.Path).
			Msg("Config reloaded")
	}
}

func (c *fileCredentials) register(cw watcher.Watcher) error {
	if err := cw.Add(c.Path, c); err != nil {
		return errorchain.NewWithMessagef(heimdall.ErrInternal,
			"failed registering client credentials watcher on %s for Redis client", c.Path).CausedBy(err)
	}

	return nil
}

func (c *fileCredentials) get() rueidis.AuthCredentials {
	c.mut.Lock()
	defer c.mut.Unlock()

	return c.creds.get()
}

type tlsConfig struct {
	config.TLS `mapstructure:",squash"`

	Disabled bool `mapstructure:"disabled"`
}

type baseConfig struct {
	Credentials   credentials        `mapstructure:"credentials"`
	ClientCache   clientCache        `mapstructure:"client_cache"`
	BufferLimit   config.BufferLimit `mapstructure:"buffer_limit"`
	Timeout       config.Timeout     `mapstructure:"timeout"`
	MaxFlushDelay time.Duration      `mapstructure:"max_flush_delay"`
	TLS           tlsConfig          `mapstructure:"tls"`
}

func (c baseConfig) clientOptions(cw watcher.Watcher) (rueidis.ClientOption, error) {
	var (
		tlsCfg *tls.Config
		err    error
	)

	if !c.TLS.Disabled {
		tlsCfg, err = tlsx.ToTLSConfig(&c.TLS.TLS,
			tlsx.WithClientAuthentication(len(c.TLS.KeyStore.Path) != 0),
			tlsx.WithSecretsWatcher(cw),
		)
		if err != nil {
			return rueidis.ClientOption{}, errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed creating tls configuration for Redis client").CausedBy(err)
		}

		tlsCfg.RootCAs = rootCertPool
	}

	if c.Credentials != nil {
		if err = c.Credentials.register(cw); err != nil {
			return rueidis.ClientOption{}, err
		}
	}

	return rueidis.ClientOption{
		ClientName:          "heimdall",
		DisableCache:        c.ClientCache.Disabled,
		CacheSizeEachConn:   int(c.ClientCache.SizePerConnection),
		WriteBufferEachConn: int(c.BufferLimit.Write),
		ReadBufferEachConn:  int(c.BufferLimit.Read),
		ConnWriteTimeout:    c.Timeout.Write,
		MaxFlushDelay:       c.MaxFlushDelay,

		AuthCredentialsFn: func(_ rueidis.AuthCredentialsContext) (rueidis.AuthCredentials, error) {
			if c.Credentials != nil {
				return c.Credentials.get(), nil
			}

			return rueidis.AuthCredentials{}, nil
		},

		DialFn: func(addr string, dialer *net.Dialer, _ *tls.Config) (net.Conn, error) {
			if tlsCfg != nil {
				return tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
			}

			return dialer.Dial("tcp", addr)
		},
	}, nil
}
