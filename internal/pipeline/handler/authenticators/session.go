package authenticators

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/stringsx"
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
	var (
		subjectId  string
		attributes map[string]interface{}
	)

	rawSubjectId := []byte(stringsx.Coalesce(gjson.GetBytes(rawData, s.SubjectFrom).Raw, "null"))
	if err := json.Unmarshal(rawSubjectId, &subjectId); err != nil {
		return nil, fmt.Errorf("configured subject_from GJSON path returned an error on JSON output: %w", err)
	}

	attributesFrom := "@this"
	if len(s.AttributesFrom) != 0 {
		attributesFrom = s.AttributesFrom
	}
	rawAttributes := []byte(stringsx.Coalesce(gjson.GetBytes(rawData, attributesFrom).Raw, "null"))
	if err := json.Unmarshal(rawAttributes, &attributes); err != nil {
		return nil, fmt.Errorf("configured attributes_from GJSON path returned an error on JSON output: %w", err)
	}

	return &heimdall.Subject{
		Id:         subjectId,
		Attributes: attributes,
	}, nil
}
