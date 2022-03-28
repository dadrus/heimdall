package authenticators

import (
	"encoding/json"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type SubjectExtrator interface {
	GetSubject(rawData json.RawMessage) (*heimdall.Subject, error)
}
