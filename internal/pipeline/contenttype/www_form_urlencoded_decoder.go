package contenttype

import (
	"net/url"
)

type WWWFormUrlencodedDecoder struct{}

func (WWWFormUrlencodedDecoder) Decode(rawData []byte) (any, error) {
	return url.ParseQuery(string(rawData))
}
