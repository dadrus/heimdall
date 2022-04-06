package authenticators

import (
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type SubjectExtrator interface {
	GetSubject(rawData []byte) (*subject.Subject, error)
}
