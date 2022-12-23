package testsupport

import (
	"github.com/knadh/koanf/maps"
	"gopkg.in/yaml.v3"
)

func DecodeTestConfig(data []byte) (map[string]any, error) {
	var out map[string]any
	err := yaml.Unmarshal(data, &out)

	maps.IntfaceKeysToStrings(out)

	return out, err
}
