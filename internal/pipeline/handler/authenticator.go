package handler

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type Authenticator interface {
	Authenticate(heimdall.Context) (*subject.Subject, error)
	WithConfig(config map[string]any) (Authenticator, error)
}
