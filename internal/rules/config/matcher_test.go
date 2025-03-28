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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatcherDeepCopyInto(t *testing.T) {
	t.Parallel()

	trueValue := true

	for uc, tc := range map[string]*Matcher{
		"single route defining only a path": {
			Routes: []Route{{Path: "/foo/bar"}},
		},
		"single route defining path and some path parameters": {
			Routes: []Route{
				{
					Path: "/:foo/:bar",
					PathParams: []ParameterMatcher{
						{Name: "foo", Value: "bar", Type: "glob"},
						{Name: "bar", Value: "baz", Type: "regex"},
					},
				},
			},
		},
		"multiple routes and additional constraints": {
			Routes: []Route{
				{
					Path: "/:foo/:bar",
					PathParams: []ParameterMatcher{
						{Name: "foo", Value: "bar", Type: "glob"},
						{Name: "bar", Value: "baz", Type: "regex"},
					},
				},
				{
					Path: "/some/static/path",
				},
			},
			BacktrackingEnabled: &trueValue,
			Scheme:              "https",
			Hosts: []HostMatcher{
				{
					Value: "*example.com",
					Type:  "glob",
				},
			},
			Methods: []string{"GET", "POST"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			out := new(Matcher)

			tc.DeepCopyInto(out)

			assert.Equal(t, tc, out)
		})
	}
}
