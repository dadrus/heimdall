package fswatch

import "github.com/rs/zerolog"

type config struct {
	logger zerolog.Logger
}

// Option configures a Watcher.
type Option func(*config)

// WithLogger configures the logger used by the watcher.
func WithLogger(logger zerolog.Logger) Option {
	return func(cfg *config) {
		cfg.logger = logger
	}
}

func applyOptions(opts []Option) config {
	cfg := config{
		logger: zerolog.Nop(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}
