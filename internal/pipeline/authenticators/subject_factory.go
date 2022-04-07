package authenticators

import (
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type SubjectFactory interface {
	CreateSubject(rawData []byte) (*subject.Subject, error)
}
