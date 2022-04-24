package authenticators

import (
	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type Session struct {
	SubjectIDFrom         string `mapstructure:"subject_id_from"`
	SubjectAttributesFrom string `mapstructure:"subject_attributes_from"`
}

func (s *Session) Validate() error {
	if len(s.SubjectIDFrom) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no subject_from set")
	}

	return nil
}

func (s *Session) CreateSubject(rawData []byte) (*subject.Subject, error) {
	attributesFrom := "@this"
	if len(s.SubjectAttributesFrom) != 0 {
		attributesFrom = s.SubjectAttributesFrom
	}

	subjectID := gjson.GetBytes(rawData, s.SubjectIDFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract subject identifier using '%s' template", s.SubjectIDFrom)
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
