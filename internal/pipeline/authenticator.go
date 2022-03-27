package pipeline

import (
	"context"
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Authenticator interface {
	Authenticate(context.Context, interfaces.AuthDataSource, *heimdall.SubjectContext) error
	WithConfig(config json.RawMessage) (Authenticator, error)
}
