package contenttype

import (
	"errors"
	"strings"
)

var ErrUnsupportedContentType = errors.New("unsupported mime type")

type Decoder interface {
	Decode(data []byte) (map[string]any, error)
}

func NewDecoder(contentType string) (Decoder, error) {
	switch {
	case strings.Contains(contentType, "json"):
		return JSONDecoder{}, nil
	case contentType == "application/x-www-form-urlencoded":
		return WWWFormUrlencodedDecoder{}, nil
	default:
		return nil, ErrUnsupportedContentType
	}
}
