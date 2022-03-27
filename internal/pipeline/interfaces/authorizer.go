package interfaces

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Authorizer interface {
	Authorize(context.Context, *heimdall.SubjectContext) error
	WithConfig(config json.RawMessage) (Authorizer, error)
}
