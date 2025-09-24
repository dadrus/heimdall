// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/common"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

var (
	ErrRequestSchemeMismatch = errors.New("request scheme mismatch")
	ErrRequestMethodMismatch = errors.New("request method mismatch")
	ErrRequestHostMismatch   = errors.New("request host mismatch")
	ErrRequestPathMismatch   = errors.New("request path mismatch")
)

type RouteMatcher interface {
	Matches(request *heimdall.Request, keys, values []string) error
}

type andMatcher []RouteMatcher

func (c andMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	for _, matcher := range c {
		if err := matcher.Matches(request, keys, values); err != nil {
			return err
		}
	}

	return nil
}

type orMatcher []RouteMatcher

func (c orMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	var err error

	for _, matcher := range c {
		if err = matcher.Matches(request, keys, values); err == nil {
			return nil
		}
	}

	return err
}

type schemeMatcher string

func (s schemeMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(s) != 0 && string(s) != request.URL.Scheme {
		return errorchain.NewWithMessagef(ErrRequestSchemeMismatch, "expected '%s', got '%s'", s, request.URL.Scheme)
	}

	return nil
}

type methodMatcher []string

func (m methodMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(m) == 0 {
		return nil
	}

	if !slices.Contains(m, request.Method) {
		return errorchain.NewWithMessagef(ErrRequestMethodMismatch, "'%s' is not expected", request.Method)
	}

	return nil
}

type pathParamMatcher struct {
	typedMatcher

	name          string
	slashHandling common.EncodedSlashesHandling
}

func (m *pathParamMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	idx := slices.Index(keys, m.name)
	if idx == -1 {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch, "path parameter '%s' is not expected", m.name)
	}

	value := values[idx]
	// URL.RawPath is set only if the original url contains url encoded parts
	if len(request.URL.RawPath) != 0 {
		switch m.slashHandling {
		case common.EncodedSlashesOff:
			if strings.Contains(request.URL.RawPath, "%2F") {
				return errorchain.NewWithMessage(ErrRequestPathMismatch,
					"request path contains encoded slashes which are not allowed")
			}
		case common.EncodedSlashesOn:
			value, _ = url.PathUnescape(value)
		default:
			unescaped, _ := url.PathUnescape(strings.ReplaceAll(value, "%2F", "$$$escaped-slash$$$"))
			value = strings.ReplaceAll(unescaped, "$$$escaped-slash$$$", "%2F")
		}
	}

	if !m.match(value) {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch,
			"captured value '%s' for path parameter '%s' is not expected", value, m.name)
	}

	return nil
}

func createMethodMatcher(methods []string) (methodMatcher, error) {
	if len(methods) == 0 {
		return methodMatcher{}, nil
	}

	if slices.Contains(methods, "ALL") {
		methods = slices.DeleteFunc(methods, func(method string) bool { return method == "ALL" })

		methods = append(methods,
			http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace)
	}

	slices.SortFunc(methods, strings.Compare)

	methods = slices.Compact(methods)
	if res := slicex.Filter(methods, func(s string) bool { return len(s) == 0 }); len(res) != 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"methods list contains empty values. "+
				"have you forgotten to put the corresponding value into braces?")
	}

	tbr := slicex.Filter(methods, func(s string) bool { return strings.HasPrefix(s, "!") })
	methods = slicex.Subtract(methods, tbr)
	tbr = slicex.Map[string, string](tbr, func(s string) string { return strings.TrimPrefix(s, "!") })

	return slicex.Subtract(methods, tbr), nil
}

func createPathParamsMatcher(
	params []v1beta1.ParameterMatcher,
	esh common.EncodedSlashesHandling,
) (RouteMatcher, error) {
	matchers := make(andMatcher, len(params))

	for idx, param := range params {
		var (
			tm  typedMatcher
			err error
		)

		switch param.Type {
		case "glob":
			tm, err = newGlobMatcher(param.Value, '/')
		case "regex":
			tm, err = newRegexMatcher(param.Value)
		case "exact":
			tm = newExactMatcher(param.Value)
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported path parameter expression type '%s' for parameter '%s' at index %d",
				param.Type, param.Name, idx)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile path params matching expression for parameter '%s' at index %d",
				param.Name, idx).
				CausedBy(err)
		}

		matchers[idx] = &pathParamMatcher{tm, param.Name, esh}
	}

	return matchers, nil
}
