package rules

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

//go:generate mockery --name errorHandler --structname ErrorHandlerMock

type errorHandler interface {
	CanExecute(ctx heimdall.Context, causeErr error) bool
	Execute(ctx heimdall.Context, causeErr error) error
}
