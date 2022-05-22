package testsupport

import (
	"gopkg.in/yaml.v2"
)

func DecodeTestConfig(data []byte) (map[string]any, error) {
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}
