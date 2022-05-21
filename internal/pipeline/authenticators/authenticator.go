package authenticators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type Authenticator interface {
	Execute(heimdall.Context) (*subject.Subject, error)
	WithConfig(config map[string]any) (Authenticator, error)
}
