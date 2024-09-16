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

	for _, tc := range []struct {
		uc string
		in *Matcher
	}{
		{
			uc: "single route defining only a path",
			in: &Matcher{
				Routes: []Route{{Path: "/foo/bar"}},
			},
		},
		{
			uc: "single route defining path and some path parameters",
			in: &Matcher{
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
		},
		{
			uc: "multiple routes and additional constraints",
			in: &Matcher{
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
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			out := new(Matcher)

			tc.in.DeepCopyInto(out)

			assert.Equal(t, tc.in, out)
		})
	}
}
