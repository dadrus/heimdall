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
	var e extractors.CompositeExtractor
	if len(s.Cookie) != 0 {
		e = append(e, extractors.CookieExtractor(s.Cookie))
	} else if len(s.Header) != 0 {
		e = append(e, &extractors.HeaderExtractor{
			HeaderName: s.Header, ValuePrefix: s.StripPrefix,
		})
	} else if len(s.QueryParameter) != 0 {
		e = append(e, extractors.QueryExtractor(s.QueryParameter))
	} else {
		return nil, errors.New("missing auth data extractor")
	}
	return e, nil
}
