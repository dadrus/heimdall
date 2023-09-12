package rule

import (
	"net/url"
	"time"
)

//go:generate mockery --name Backend --structname BackendMock

type Backend interface {
	URL() *url.URL
	ReadTimeout() *time.Duration
	WriteTimeout() *time.Duration
}
