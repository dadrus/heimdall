package rules

import "github.com/dadrus/heimdall/internal/heimdall"

type errorHandler interface {
	Execute(ctx heimdall.Context, err error) (bool, error)
}
