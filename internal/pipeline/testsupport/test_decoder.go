package testsupport

import "gopkg.in/yaml.v2"

func DecodeTestConfig(data []byte) (map[any]any, error) {
	var res map[any]any

	err := yaml.Unmarshal(data, &res)

	return res, err
}
