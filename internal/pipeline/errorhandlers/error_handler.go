package errorhandlers

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

type ErrorHandler interface {
	Execute(ctx heimdall.Context, err error) (bool, error)
	WithConfig(config map[string]any) (ErrorHandler, error)
}
