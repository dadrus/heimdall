package pipeline

import (
	"context"
)

type ErrorHandler interface {
	HandleError(ctx context.Context, err error) error
}
