package handler

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Authorizer interface {
	Authorize(context.Context, RequestContext, *heimdall.SubjectContext) error
	WithConfig(config json.RawMessage) (Authorizer, error)
}
