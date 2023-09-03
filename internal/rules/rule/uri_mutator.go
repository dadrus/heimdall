package rule

import "net/url"

//go:generate mockery --name URIMutator --structname URIMutatorMock

type URIMutator interface {
	Mutate(uri *url.URL) (*url.URL, error)
}
