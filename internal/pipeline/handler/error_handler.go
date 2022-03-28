package handler

import (
	"context"
)

type ErrorHandler interface {
	HandleError(ctx context.Context, err error) error
	WithConfig(config []byte) (ErrorHandler, error)
}
