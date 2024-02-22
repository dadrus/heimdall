package redis

import (
	"time"

	"github.com/inhies/go-bytesize"

	"github.com/dadrus/heimdall/internal/config"
)

type clientCache struct {
	Disabled          bool              `mapstructure:"disabled"`
	TTL               time.Duration     `mapstructure:"ttl"`
	SizePerConnection bytesize.ByteSize `mapstructure:"size_per_connection"`
}

type credentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type baseConfig struct {
	Credentials   credentials        `mapstructure:"credentials"`
	ClientCache   clientCache        `mapstructure:"client_cache"`
	BufferLimit   config.BufferLimit `mapstructure:"buffer_limit"`
	Timeout       config.Timeout     `mapstructure:"timeout"`
	MaxFlushDelay time.Duration      `mapstructure:"max_flush_delay"`
}
