package contenttype

import (
	"net/url"
)

type WWWFormUrlencodedDecoder struct{}

func (WWWFormUrlencodedDecoder) Decode(rawData []byte) (any, error) {
	values, err := url.ParseQuery(string(rawData))
	if err != nil {
		return nil, err
	}

	return values, nil
}
