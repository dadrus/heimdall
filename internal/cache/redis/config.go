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
		tlsCfg, err = c.TLS.TLSConfig()
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
