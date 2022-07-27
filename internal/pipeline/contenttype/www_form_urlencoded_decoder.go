package contenttype

import (
	"net/url"
)

type WWWFormUrlencodedDecoder struct{}

func (WWWFormUrlencodedDecoder) Decode(rawData []byte) (map[string]any, error) {
	values, err := url.ParseQuery(string(rawData))
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(values))
	for k, v := range values {
		result[k] = v
	}

	return result, nil
}
