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

package cachekey

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuilder(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		key1        func() string
		key2        func() string
		expectEqual bool
	}{
		"same values": {
			key1: func() string {
				key := New("test")
				key.WriteString("foo")
				key.WriteBytes([]byte("bar"))
				key.WriteBool(true)
				key.WriteUint64(42)
				key.WriteInt64(-42)

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteString("foo")
				key.WriteBytes([]byte("bar"))
				key.WriteBool(true)
				key.WriteUint64(42)
				key.WriteInt64(-42)

				return key.SumString()
			},
			expectEqual: true,
		},
		"different domain": {
			key1: func() string {
				key := New("foo")
				key.WriteString("bar")

				return key.SumString()
			},
			key2: func() string {
				key := New("foobar")
				key.WriteString("")

				return key.SumString()
			},
		},
		"string boundaries are preserved": {
			key1: func() string {
				key := New("test")
				key.WriteString("a")
				key.WriteString("bc")

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteString("ab")
				key.WriteString("c")

				return key.SumString()
			},
		},
		"byte boundaries are preserved": {
			key1: func() string {
				key := New("test")
				key.WriteBytes([]byte("a"))
				key.WriteBytes([]byte("bc"))

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteBytes([]byte("ab"))
				key.WriteBytes([]byte("c"))

				return key.SumString()
			},
		},
		"string slice boundaries are preserved": {
			key1: func() string {
				key := New("test")
				key.WriteStrings([]string{"a", "bc"})

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteStrings([]string{"ab", "c"})

				return key.SumString()
			},
		},
		"different bool": {
			key1: func() string {
				key := New("test")
				key.WriteBool(false)

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteBool(true)

				return key.SumString()
			},
		},
		"different uint64": {
			key1: func() string {
				key := New("test")
				key.WriteUint64(1)

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteUint64(2)

				return key.SumString()
			},
		},
		"different int64": {
			key1: func() string {
				key := New("test")
				key.WriteInt64(-1)

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteInt64(1)

				return key.SumString()
			},
		},
		"presence can distinguish absent and empty values": {
			key1: func() string {
				key := New("test")
				key.WriteBool(false)

				return key.SumString()
			},
			key2: func() string {
				key := New("test")
				key.WriteBool(true)
				key.WriteBytes(nil)

				return key.SumString()
			},
		},
		"headers are independent of map insertion order": {
			key1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "foo")
				header.Set("X-Bar", "bar")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			key2: func() string {
				header := make(http.Header)
				header.Set("X-Bar", "bar")
				header.Set("X-Foo", "foo")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			expectEqual: true,
		},
		"different header name": {
			key1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "value")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			key2: func() string {
				header := make(http.Header)
				header.Set("X-Bar", "value")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
		},
		"different header value": {
			key1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "foo")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			key2: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "bar")

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
		},
		"header value boundaries are preserved": {
			key1: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"a", "bc"}

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			key2: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"ab", "c"}

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
		},
		"header value order is preserved": {
			key1: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"foo", "bar"}

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
			key2: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"bar", "foo"}

				key := New("test")
				key.WriteHeader(header)

				return key.SumString()
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			key1 := tc.key1()
			key2 := tc.key2()

			// THEN
			if tc.expectEqual {
				assert.Equal(t, key1, key2)
			} else {
				assert.NotEqual(t, key1, key2)
			}
		})
	}
}
