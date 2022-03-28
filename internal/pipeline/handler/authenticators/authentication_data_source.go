package authenticators

import (
	"errors"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
)

type authenticationDataSource struct {
	es extractors.AuthDataExtractStrategy
}

func (a *authenticationDataSource) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	a.es, err = doUnmarshal(unmarshal)
	return err
}

func doUnmarshal(unmarshal func(interface{}) error) (extractors.AuthDataExtractStrategy, error) {
	var strategies extractors.CompositeExtractStrategy
	var sources []map[string]string

	if err := unmarshal(&sources); err != nil {
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
