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
	"slices"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

// nolint: gochecknoglobals
var spaceReplacer = strings.NewReplacer("\t", "", "\n", "", "\v", "", "\f", "", "\r", "", " ", "")

var (
	ErrRequestSchemeMismatch = errors.New("request scheme mismatch")
	ErrRequestMethodMismatch = errors.New("request method mismatch")
	ErrRequestHostMismatch   = errors.New("request host mismatch")
	ErrRequestPathMismatch   = errors.New("request path mismatch")
)

type RouteMatcher interface {
	Matches(request *heimdall.Request, keys, values []string) error
}

type compositeMatcher []RouteMatcher

func (c compositeMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	for _, matcher := range c {
		if err := matcher.Matches(request, keys, values); err != nil {
			return err
		}
	}

	return nil
}

type schemeMatcher string

func (s schemeMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(s) != 0 && string(s) != request.URL.Scheme {
		return errorchain.NewWithMessagef(ErrRequestSchemeMismatch, "expected %s, got %s", s, request.URL.Scheme)
	}

	return nil
}

type methodMatcher []string

func (m methodMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(m) == 0 {
		return nil
	}

	if !slices.Contains(m, request.Method) {
		return errorchain.NewWithMessagef(ErrRequestMethodMismatch, "%s is not expected", request.Method)
	}

	return nil
}

type hostMatcher struct {
	typedMatcher
}

func (m *hostMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if !m.match(request.URL.Host) {
		return errorchain.NewWithMessagef(ErrRequestHostMismatch, "%s is not expected", request.URL.Host)
	}

	return nil
}

type pathParamMatcher struct {
	typedMatcher

	name          string
	slashHandling config.EncodedSlashesHandling
}

func (m *pathParamMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	idx := slices.Index(keys, m.name)
	if idx == -1 {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch, "path parameter %s is not expected", m.name)
	}

	value := values[idx]
	// URL.RawPath is set only if the original url contains url encoded parts
	if len(request.URL.RawPath) != 0 &&
		m.slashHandling == config.EncodedSlashesOff &&
		strings.Contains(request.URL.RawPath, "%2F") {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch,
			"value for path parameter %s contains encoded slashes which are not allowed", keys[idx])
	}

	if !m.match(value) {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch,
			"captured values for path parameter %s is not expected", value)
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

func createHostMatcher(hosts []config.HostMatcher) (RouteMatcher, error) {
	matchers := make(compositeMatcher, len(hosts))

	for idx, host := range hosts {
		var (
			tm  typedMatcher
			err error
		)

		switch host.Type {
		case "glob":
			tm, err = newGlobMatcher(host.Value, '.')
		case "regex":
			tm, err = newRegexMatcher(host.Value)
		case "exact":
			tm, err = newExactMatcher(host.Value)
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported host matching expression type '%s' at index %d", host.Type, idx)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"failed to compile host matching expression at index %d", idx).CausedBy(err)
		}

		matchers[idx] = &hostMatcher{tm}
	}

	return matchers, nil
}

func createPathParamsMatcher(params []config.ParameterMatcher, esh config.EncodedSlashesHandling) (RouteMatcher, error) {
	matchers := make(compositeMatcher, len(params))

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
			tm, err = newExactMatcher(param.Value)
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
