package authenticators

import (
	"encoding/json"

	"github.com/dadrus/heimdall/pipeline"
)

type SubjectExtrator interface {
	GetSubject(rawData json.RawMessage) (*pipeline.Subject, error)
}
