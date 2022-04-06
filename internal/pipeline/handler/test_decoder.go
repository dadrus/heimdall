package handler

import "gopkg.in/yaml.v2"

func DecodeTestConfig(data []byte) (map[string]interface{}, error) {
	var res map[string]interface{}

	err := yaml.Unmarshal(data, &res)

	return res, err
}
