package pipeline

import (
	"context"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/interfaces"
)

type Authenticator interface {
	Authenticate(context.Context, interfaces.AuthDataSource, *heimdall.SubjectContext) error
}
