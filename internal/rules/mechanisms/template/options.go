package template

import (
	"github.com/dadrus/heimdall/internal/secrets"
)

const defaultTemplateName = "Heimdall"

type Option func(*options)

type options struct {
	name             string
	resolver         secrets.Resolver
	secretsForbidden bool
}

func WithName(name string) Option {
	return func(opts *options) {
		if len(name) != 0 {
			opts.name = name
		}
	}
}

func WithSecretResolver(resolver secrets.Resolver) Option {
	return func(opts *options) {
		if resolver != nil {
			opts.resolver = resolver
		}
	}
}

func WithSecretsForbidden() Option {
	return func(opts *options) {
		opts.secretsForbidden = true
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