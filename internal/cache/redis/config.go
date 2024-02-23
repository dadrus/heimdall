package redis

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/inhies/go-bytesize"
	"github.com/redis/rueidis"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// for test purposes only
var rootCertPool *x509.CertPool //nolint:gochecknoglobals

type clientCache struct {
	Disabled          bool              `mapstructure:"disabled"`
	TTL               time.Duration     `mapstructure:"ttl"`
	SizePerConnection bytesize.ByteSize `mapstructure:"size_per_connection"`
}

type credentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
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

func (c baseConfig) clientOptions() (rueidis.ClientOption, error) {
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

	return rueidis.ClientOption{
		ClientName:          "heimdall",
		Username:            c.Credentials.Username,
		Password:            c.Credentials.Password,
		DisableCache:        c.ClientCache.Disabled,
		CacheSizeEachConn:   int(c.ClientCache.SizePerConnection),
		WriteBufferEachConn: int(c.BufferLimit.Write),
		ReadBufferEachConn:  int(c.BufferLimit.Read),
		ConnWriteTimeout:    c.Timeout.Write,
		MaxFlushDelay:       c.MaxFlushDelay,
		TLSConfig:           tlsCfg,
	}, nil
}
