package logger

type config struct {
	logAccessStatus  bool
	accessLogEnabled bool
}

type Option func(*config)

func WithAccessStatusEnabled(flag bool) Option {
	return func(c *config) {
		c.logAccessStatus = flag
	}
}

func WithAccessLogEnabled(flag bool) Option {
	return func(c *config) {
		c.accessLogEnabled = flag
	}
}
