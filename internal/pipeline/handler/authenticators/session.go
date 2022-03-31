package authenticators

import (
	"errors"

	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Session struct {
	SubjectFrom    string `yaml:"subject_from"`
	AttributesFrom string `yaml:"attributes_from"`
}

func (s *Session) Validate() error {
	if len(s.SubjectFrom) == 0 {
		return errors.New("session requires subject_from to be set")
	}
	return nil
}

func (s *Session) GetSubject(rawData []byte) (*heimdall.Subject, error) {
	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}

	subjectId := gjson.GetBytes(rawData, s.SubjectFrom).String()
	if len(subjectId) == 0 {
		return nil, errors.New("failed to extract subject identifier")
	}
	attributes := gjson.GetBytes(rawData, attributesFrom).Value()

	return &heimdall.Subject{
		ID:         subjectId,
		Attributes: attributes,
	}, nil
}
