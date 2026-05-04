package tlsx

import (
	"github.com/dadrus/heimdall/internal/keyregistry/v2"
	"github.com/dadrus/heimdall/internal/secrets"
)

type noopObserver struct{}

func (noopObserver) Notify(_ keyregistry.KeyInfo) {}

type options struct {
	serverAuthRequired bool
	clientAuthRequired bool
	secretsManager     secrets.Manager
	keyObserver        keyregistry.KeyObserver
}

func newOptions() *options {
	return &options{keyObserver: noopObserver{}}
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

func WithSecretsManager(manager secrets.Manager) Option {
	return func(o *options) {
		o.secretsManager = manager
	}
}

func WithKeyObserver(observer keyregistry.KeyObserver) Option {
	return func(o *options) {
		if observer != nil {
			o.keyObserver = observer
		}
	}
}
