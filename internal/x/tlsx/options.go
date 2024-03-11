package tlsx

import "github.com/dadrus/heimdall/internal/watcher"

type options struct {
	serverAuthRequired bool
	clientAuthRequired bool
	secretsWatcher     watcher.Watcher
}

type Option func(*options)

func WithServerAuthentication(flag bool) Option {
	return func(o *options) {
		o.serverAuthRequired = flag
	}
}

func WithClientAuthentication(flag bool) Option {
	return func(o *options) {
		o.clientAuthRequired = flag
	}
}

func WithSecretsWatcher(cw watcher.Watcher) Option {
	return func(o *options) {
		o.secretsWatcher = cw
	}
}
