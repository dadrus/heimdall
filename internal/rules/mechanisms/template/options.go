package template

import (
	store2 "github.com/dadrus/heimdall/internal/secrets"
)

const defaultTemplateName = "Heimdall"

type Option func(*options)

type options struct {
	name  string
	store store2.Store
}

func WithName(name string) Option {
	return func(opts *options) {
		if len(name) != 0 {
			opts.name = name
		}
	}
}

func WithSecretStore(store store2.Store) Option {
	return func(opts *options) {
		opts.store = store
	}
}

func applyOptions(opts ...Option) options {
	cfg := options{name: defaultTemplateName}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return cfg
}
