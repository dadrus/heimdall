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

func (s *Session) CreateSubject(rawData []byte) (*subject.Subject, error) {
	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}

	subjectID := gjson.GetBytes(rawData, s.SubjectFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract subject identifier using '%s' template", s.SubjectFrom)
	}

	attributes := gjson.GetBytes(rawData, attributesFrom).Value()
	if attributes == nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract attributes using '%s' template", attributesFrom)
	}

	attrs, ok := attributes.(map[string]any)
	if !ok {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "unexpected response from gjson template")
	}

	return &subject.Subject{
		ID:         subjectID,
		Attributes: attrs,
	}, nil
}
