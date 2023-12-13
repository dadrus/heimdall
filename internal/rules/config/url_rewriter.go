// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

	rawPath := r.transformPath(value.EscapedPath())
	if len(value.RawPath) != 0 {
		// if the original url path had url encoded parts
		value.RawPath = rawPath
	}

	value.Path, _ = url.PathUnescape(rawPath)
	if value.Path != rawPath {
		// if the new path contains url encoded parts
		value.RawPath = rawPath
	}

	value.RawQuery = r.transformQuery(value.RawQuery)
}

func (r *URLRewriter) transformPath(value string) string {
	return r.PathPrefixToAdd.AddTo(r.PathPrefixToCut.CutFrom(value))
}

func (r *URLRewriter) transformQuery(value string) string {
	return r.QueryParamsToRemove.RemoveFrom(value)
}
