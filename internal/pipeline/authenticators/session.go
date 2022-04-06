package authenticators

import (
	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Session struct {
	SubjectFrom    string `mapstructure:"subject_from"`
	AttributesFrom string `mapstructure:"attributes_from"`
}

func (s *Session) Validate() error {
	if len(s.SubjectFrom) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no subject_from set")
	}

	return nil
}

func (s *Session) GetSubject(rawData []byte) (*subject.Subject, error) {
	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}

	subjectID := gjson.GetBytes(rawData, s.SubjectFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal, "no value available for \"%s\" claim", s.SubjectFrom)
	}

	attributes := gjson.GetBytes(rawData, attributesFrom).Value()

	return &subject.Subject{
		ID:         subjectID,
		Attributes: attributes,
	}, nil
}
