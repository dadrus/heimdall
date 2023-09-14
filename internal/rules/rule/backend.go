package rule

import (
	"net/url"
)

//go:generate mockery --name Backend --structname BackendMock

type Backend interface {
	URL() *url.URL
}
