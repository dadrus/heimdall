package testsupport

import (
	"gopkg.in/yaml.v3"
)

func DecodeTestConfig(data []byte) (map[string]any, error) {
	var out map[string]any
	err := yaml.Unmarshal(data, &out)

	return out, err
}
