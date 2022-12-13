package authenticators

import (
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type SubjectFactory interface {
	CreateSubject(rawData []byte) (*subject.Subject, error)
}
