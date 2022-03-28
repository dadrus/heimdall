package authenticators

import (
	"github.com/dadrus/heimdall/internal/heimdall"
)

type SubjectExtrator interface {
	GetSubject(rawData []byte) (*heimdall.Subject, error)
}
