package contenttype

import (
	"github.com/goccy/go-json"
)

type JSONDecoder struct{}

func (JSONDecoder) Decode(rawData []byte) (map[string]any, error) {
	var mapData map[string]any
	if err := json.Unmarshal(rawData, &mapData); err != nil {
		return nil, err
	}

	return mapData, nil
}
