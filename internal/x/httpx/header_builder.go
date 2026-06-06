package httpx

import "strings"

type headerBuilder struct {
	prefix string
	parts  []string
}

func NewHeader(options ...Option) string {
	h := headerBuilder{}
	for _, opt := range options {
		opt(&h)
	}

	return h.build()
}

func (b headerBuilder) build() string {
	return b.prefix + strings.Join(b.parts, ", ")
}

type Option func(*headerBuilder)

func WithPrefix(value string) Option {
	return func(builder *headerBuilder) {
		if len(value) != 0 {
			builder.prefix = value + " "
		}
	}
}

func WithKeyValue(key, value string) Option {
	return func(builder *headerBuilder) {
		if len(key) != 0 && len(value) != 0 {
			builder.parts = append(builder.parts, key+"=\""+value+"\"")
		}
	}
}

func WithValue(value string) Option {
	return func(builder *headerBuilder) {
		if len(value) != 0 {
			builder.parts = append(builder.parts, value)
		}
	}
}
