package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/dadrus/heimdall/internal/x"
)

type PrefixCutter string

func (c PrefixCutter) CutFrom(value string) string {
	if len(c) != 0 {
		res, _ := strings.CutPrefix(value, string(c))

		return res
	}

	return value
}

type PrefixAdder string

func (a PrefixAdder) AddTo(value string) string {
	if len(a) != 0 {
		return fmt.Sprintf("%s%s", a, value)
	}

	return value
}

type QueryParamsRemover []string

func (r QueryParamsRemover) RemoveFrom(value string) string {
	if len(value) == 0 || len(r) == 0 {
		return value
	}

	query, err := url.ParseQuery(value)
	if err != nil {
		return value
	}

	for _, param := range r {
		query.Del(param)
	}

	return query.Encode()
}

type URLRewriter struct {
	Scheme              string             `json:"scheme"                 yaml:"scheme"`
	PathPrefixToCut     PrefixCutter       `json:"strip_path_prefix"      yaml:"strip_path_prefix"`
	PathPrefixToAdd     PrefixAdder        `json:"add_path_prefix"        yaml:"add_path_prefix"`
	QueryParamsToRemove QueryParamsRemover `json:"strip_query_parameters" yaml:"strip_query_parameters"`
}

func (r *URLRewriter) Rewrite(value *url.URL) {
	value.Scheme = x.IfThenElseExec(
		len(r.Scheme) != 0,
		func() string { return r.Scheme },
		func() string { return value.Scheme },
	)
	value.Path = r.transformPath(value.Path)
	value.RawQuery = r.transformQuery(value.RawQuery)
}

func (r *URLRewriter) transformPath(value string) string {
	return r.PathPrefixToAdd.AddTo(r.PathPrefixToCut.CutFrom(value))
}

func (r *URLRewriter) transformQuery(value string) string {
	return r.QueryParamsToRemove.RemoveFrom(value)
}
