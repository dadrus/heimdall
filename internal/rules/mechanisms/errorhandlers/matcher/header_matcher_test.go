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

package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		headers  map[string][]string
		match    map[string]string
		matching bool
	}{
		{
			uc: "match single header",
			headers: map[string][]string{
				"foobar": {"foo", "bar"},
			},
			match:    map[string]string{"Foobar": "bar,baz"},
			matching: true,
		},
		{
			uc: "match multiple header",
			headers: map[string][]string{
				"foobar":               {"foo", "bar"},
				"some-header":          {"value1", "value2"},
				"x-yet-another-header": {"application/json"},
			},
			match: map[string]string{
				"Foobar":               "bar,foo",
				"Some-Header":          "value1,val3",
				"X-Yet-Another-Header": "application/xml;q=0.8, application/json;v=1.2",
			},
			matching: true,
		},
		{
			uc: "don't match header",
			headers: map[string][]string{
				"foobar":      {"foo", "bar"},
				"some-header": {"value1", "value2"},
			},
			match:    map[string]string{"Barfoo": "bar"},
			matching: false,
		},
		{
			uc: "don't match header value",
			headers: map[string][]string{
				"foobar":      {"foo", "bar"},
				"some-header": {"value1", "value2"},
			},
			match:    map[string]string{"Foobar": "value1"},
			matching: false,
		},
		{
			uc: "match header case-insensitivity",
			headers: map[string][]string{
				"x-foo-bar": {"bar"},
				"X-Bar-foo": {"foo"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar",
				"X-Bar-Foo": "foo",
			},
			matching: true,
		},
		{
			uc: "match simple header value using *",
			headers: map[string][]string{
				"x-foo-bar": {"*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar",
			},
			matching: true,
		},
		{
			uc: "match structured header value using *",
			headers: map[string][]string{
				"x-foo-bar": {"*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,foo/bar",
			},
			matching: true,
		},
		{
			uc: "do not match simple header value using */*",
			headers: map[string][]string{
				"x-foo-bar": {"*/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar",
			},
			matching: false,
		},
		{
			uc: "match structured header value using */*",
			headers: map[string][]string{
				"x-foo-bar": {"*/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,foo/bar",
			},
			matching: true,
		},
		{
			uc: "match structured wildcard header value using */*",
			headers: map[string][]string{
				"x-foo-bar": {"*/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,*/*",
			},
			matching: true,
		},
		{
			uc: "do not match structured header value using text/*",
			headers: map[string][]string{
				"x-foo-bar": {"text/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,foo/bar",
			},
			matching: false,
		},
		{
			uc: "do not match structured wildcard header value using text/*",
			headers: map[string][]string{
				"x-foo-bar": {"text/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,*/*",
			},
			matching: false,
		},
		{
			uc: "do not match structured wildcard header value using */plain",
			headers: map[string][]string{
				"x-foo-bar": {"*/plain"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,*/*",
			},
			matching: false,
		},
		{
			uc: "match structured header value using text/*",
			headers: map[string][]string{
				"x-foo-bar": {"text/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,text/*",
			},
			matching: true,
		},
		{
			uc: "do not match structured header value using application/*",
			headers: map[string][]string{
				"x-foo-bar": {"application/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,text/*",
			},
			matching: false,
		},
		{
			uc: "match structured header value using text/*",
			headers: map[string][]string{
				"x-foo-bar": {"text/*"},
			},
			match: map[string]string{
				"X-Foo-Bar": "bar/foo;q=0.1;v=1,text/plain",
			},
			matching: true,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher := HeaderMatcher(tc.headers)

			// WHEN
			matched := matcher.Match(tc.match)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
