package authenticators

import (
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
)

type SubjectExtrator interface {
	GetSubject(rawData []byte) (*subject.Subject, error)
}
