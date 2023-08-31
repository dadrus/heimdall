package request

import "net/http"

//go:generate mockery --name ContextFactory --structname ContextFactoryMock

type ContextFactory interface {
	Create(rw http.ResponseWriter, req *http.Request) Context
}
