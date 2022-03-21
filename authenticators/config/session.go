package config

import (
	"encoding/json"
	"fmt"

	"github.com/ory/go-convenience/stringsx"
	"github.com/tidwall/gjson"
)

type Session struct {
	SubjectFrom    string `json:"subject_from"`
	AttributesFrom string `json:"attributes_from"`
}

func (s *Session) SubjectId(rawData json.RawMessage) (string, error) {
	var subjectId string
	rawSubjectId := []byte(stringsx.Coalesce(gjson.GetBytes(rawData, s.SubjectFrom).Raw, "null"))
	if err := json.Unmarshal(rawSubjectId, &subjectId); err != nil {
		return "", fmt.Errorf("configured subject_from GJSON path returned an error on JSON output: %w", err)
	}
	return subjectId, nil
}

func (s *Session) SubjectAttributes(rawData json.RawMessage) (map[string]interface{}, error) {
	var attributes map[string]interface{}
	rawSubjectId := []byte(stringsx.Coalesce(gjson.GetBytes(rawData, s.AttributesFrom).Raw, "null"))
	if err := json.Unmarshal(rawSubjectId, &attributes); err != nil {
		return attributes, fmt.Errorf("configured attributes_from GJSON path returned an error on JSON output: %w", err)
	}
	return attributes, nil
}
