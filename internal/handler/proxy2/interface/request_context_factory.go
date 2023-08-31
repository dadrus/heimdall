package _interface

import "net/http"

//go:generate mockery --name RequestContextFactory --structname RequestContextFactoryMock

type RequestContextFactory interface {
	Create(rw http.ResponseWriter, req *http.Request) RequestContext
}
