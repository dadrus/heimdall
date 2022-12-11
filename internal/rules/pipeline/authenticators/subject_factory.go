package authenticators

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
)

type SubjectFactory interface {
	CreateSubject(rawData []byte) (*subject.Subject, error)
}
