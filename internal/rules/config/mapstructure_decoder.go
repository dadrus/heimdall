// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"errors"
	"fmt"
	"reflect"

	"github.com/dadrus/heimdall/internal/x"
)

var (
	ErrURLMissing          = errors.New("url property not present")
	ErrURLType             = errors.New("bad url type")
	ErrStrategyType        = errors.New("bad strategy type")
	ErrUnsupportedStrategy = errors.New("unsupported strategy")
)

func matcherDecodeHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeOf(Matcher{}) {
		return data, nil
	}

	if from.Kind() != reflect.String && from.Kind() != reflect.Map {
		return data, nil
	}

	if from.Kind() == reflect.String {
		// nolint: forcetypeassert
		// already checked above
		return Matcher{URL: data.(string), Strategy: "glob"}, nil
	}

	// nolint: forcetypeassert
	// already checked above
	values := data.(map[string]any)

	var strategyValue string

	URL, urlPresent := values["url"]
	if !urlPresent {
		return nil, ErrURLMissing
	}

	urlValue, ok := URL.(string)
	if !ok {
		return nil, ErrURLType
	}

	strategy, strategyPresent := values["strategy"]
	if strategyPresent {
		strategyValue, ok = strategy.(string)
		if !ok {
			return nil, ErrStrategyType
		}

		if strategyValue != "glob" && strategyValue != "regex" {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedStrategy, strategyValue)
		}
	}

	return Matcher{
		URL:      urlValue,
		Strategy: x.IfThenElse(strategyPresent, strategyValue, "glob"),
	}, nil
}
