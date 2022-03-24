package config

import (
	"encoding/json"
	"errors"

	"github.com/dadrus/heimdall/internal/extractors"
)

type AuthenticationDataSource struct {
	es extractors.AuthDataExtractStrategy
}

func (a AuthenticationDataSource) Strategy() extractors.AuthDataExtractStrategy {
	return a.es
}

func (a *AuthenticationDataSource) UnmarshalJSON(data []byte) (err error) {
	a.es, err = authenticationDataFromJson(data)
	return err
}

func authenticationDataFromJson(raw []byte) (extractors.AuthDataExtractStrategy, error) {
	var strategies extractors.CompositeExtractStrategy
	var sources []map[string]string

	if err := json.Unmarshal(raw, &sources); err != nil {
		return nil, err
	}

	for _, s := range sources {
		prefix, _ := s["strip_prefix"]
		if v, ok := s["header"]; ok {
			strategies = append(strategies, &extractors.HeaderValueExtractStrategy{
				Name:   v,
				Prefix: prefix,
			})
		} else if v, ok := s["cookie"]; ok {
			strategies = append(strategies, &extractors.CookieValueExtractStrategy{
				Name:   v,
				Prefix: prefix,
			})
		} else if v, ok := s["query_parameter"]; ok {
			strategies = append(strategies, &extractors.QueryParameterExtractStrategy{
				Name:   v,
				Prefix: prefix,
			})
		} else if v, ok := s["form_parameter"]; ok {
			strategies = append(strategies, &extractors.FormParameterExtractStrategy{
				Name:   v,
				Prefix: prefix,
			})
		} else {
			return nil, errors.New("unsupported authentication source")
		}
	}

	return strategies, nil
}
