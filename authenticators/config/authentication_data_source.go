package config

import (
	"errors"

	"github.com/dadrus/heimdall/authenticators/extractors"
)

type AuthenticationDataSource struct {
	Header         string `json:"header"`
	QueryParameter string `json:"query_parameter"`
	Cookie         string `json:"cookie"`
	StripPrefix    string `json:"strip_prefix"`
}

func (s AuthenticationDataSource) Extractor() (extractors.AuthDataExtractor, error) {
	if len(s.Cookie) != 0 {
		return extractors.CookieExtractor(s.Cookie), nil
	} else if len(s.Header) != 0 {
		return &extractors.HeaderExtractor{
			HeaderName: s.Header, ValuePrefix: s.StripPrefix,
		}, nil
	} else if len(s.QueryParameter) != 0 {
		return extractors.QueryExtractor(s.QueryParameter), nil
	} else {
		return nil, errors.New("missing auth data extractor")
	}
}
