package logger

type config struct {
	logAccessStatus bool
}

type Option func(*config)

func WithAccessStatusEnabled(flag bool) Option {
	return func(c *config) {
		c.logAccessStatus = flag
	}
}
