package authenticators

import (
	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type SubjectInfo struct {
	IDFrom         string `mapstructure:"id"`
	AttributesFrom string `mapstructure:"attributes"`
}

func (s *SubjectInfo) Validate() error {
	if len(s.IDFrom) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no subject.id set")
	}

	return nil
}

func (s *SubjectInfo) CreateSubject(rawData []byte) (*subject.Subject, error) {
	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}

	subjectID := gjson.GetBytes(rawData, s.IDFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"could not extract subject identifier using '%s' template", s.IDFrom)
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
