package interfaces

import (
	"context"
	"encoding/json"
)

type ErrorHandler interface {
	HandleError(ctx context.Context, err error) error
	WithConfig(config json.RawMessage) (ErrorHandler, error)
}
