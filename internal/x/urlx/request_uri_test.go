// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package urlx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasFragmentDelimiter(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		target   string
		expected bool
	}{
		"regular path":            {target: "/metrics"},
		"encoded hash in path":    {target: "/metrics%23"},
		"encoded hash in query":   {target: "/metrics?foo=%23bar"},
		"hash in path":            {target: "/metrics#", expected: true},
		"hash in query":           {target: "/metrics?foo=bar#baz", expected: true},
		"hash after encoded hash": {target: "/metrics%23#baz", expected: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, HasFragmentDelimiter(tc.target))
		})
	}
}

func TestParseRequestURI(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		target  string
		path    string
		query   string
		wantErr bool
	}{
		"regular path":                {target: "/metrics", path: "/metrics"},
		"encoded hash in path":        {target: "/metrics%23", path: "/metrics%23"},
		"encoded hash in query":       {target: "/metrics?foo=%23bar", path: "/metrics", query: "foo=%23bar"},
		"regular query":               {target: "/metrics?foo=bar", path: "/metrics", query: "foo=bar"},
		"double leading slash":        {target: "//metrics", path: "//metrics"},
		"absolute request URI":        {target: "http://example.com/metrics", path: "/metrics"},
		"trailing fragment delimiter": {target: "/metrics#", wantErr: true},
		"fragment in path":            {target: "/metrics#section", wantErr: true},
		"fragment in query":           {target: "/metrics?foo=bar#section", wantErr: true},
		"double slash and fragment":   {target: "//metrics#section", wantErr: true},
		"absolute URI and fragment":   {target: "http://example.com/metrics#section", wantErr: true},
		"invalid percent escape":      {target: "/metrics%zz", wantErr: true},
		"empty request URI":           {target: "", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseRequestURI(tc.target)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, parsed)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, parsed)
			assert.Equal(t, tc.path, parsed.EscapedPath())
			assert.Equal(t, tc.query, parsed.RawQuery)
		})
	}
}
