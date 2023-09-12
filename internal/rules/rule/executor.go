package rule

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

//go:generate mockery --name Executor --structname ExecutorMock

type Executor interface {
	Execute(ctx heimdall.Context) (Backend, error)
}
