package template

const defaultTemplateName = "Heimdall"

type Option func(*options)

type options struct {
	name  string
	store SecretStore
}

func WithName(name string) Option {
	return func(opts *options) {
		if len(name) != 0 {
			opts.name = name
		}
	}
}

func WithSecretStore(store SecretStore) Option {
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
