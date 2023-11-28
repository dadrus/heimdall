package contenttype

import "gopkg.in/yaml.v3"

type YAMLDecoder struct{}

func (YAMLDecoder) Decode(rawData []byte) (map[string]any, error) {
	var mapData map[string]any
	if err := yaml.Unmarshal(rawData, &mapData); err != nil {
		return nil, err
	}

	return mapData, nil
}
