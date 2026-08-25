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
		cachebuilder1   func() string
		cachebuilder2   func() string
		expectEqual bool
	}{
		"same values": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteString("foo")
				builder.WriteBytes([]byte("bar"))
				builder.WriteBool(true)
				builder.WriteUint64(42)
				builder.WriteInt64(-42)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteString("foo")
				builder.WriteBytes([]byte("bar"))
				builder.WriteBool(true)
				builder.WriteUint64(42)
				builder.WriteInt64(-42)

				return builder.SumString()
			},
			expectEqual: true,
		},
		"different domain": {
			cachebuilder1: func() string {
				builder := New("foo")
				builder.WriteString("bar")

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("foobar")
				builder.WriteString("")

				return builder.SumString()
			},
		},
		"string boundaries are preserved": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteString("a")
				builder.WriteString("bc")

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteString("ab")
				builder.WriteString("c")

				return builder.SumString()
			},
		},
		"byte boundaries are preserved": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteBytes([]byte("a"))
				builder.WriteBytes([]byte("bc"))

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteBytes([]byte("ab"))
				builder.WriteBytes([]byte("c"))

				return builder.SumString()
			},
		},
		"string slice boundaries are preserved": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteStrings([]string{"a", "bc"})

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteStrings([]string{"ab", "c"})

				return builder.SumString()
			},
		},
		"different bool": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteBool(false)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteBool(true)

				return builder.SumString()
			},
		},
		"different uint64": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteUint64(1)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteUint64(2)

				return builder.SumString()
			},
		},
		"different int64": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteInt64(-1)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteInt64(1)

				return builder.SumString()
			},
		},
		"presence can distinguish absent and empty values": {
			cachebuilder1: func() string {
				builder := New("test")
				builder.WriteBool(false)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				builder := New("test")
				builder.WriteBool(true)
				builder.WriteBytes(nil)

				return builder.SumString()
			},
		},
		"headers are independent of map insertion order": {
			cachebuilder1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "foo")
				header.Set("X-Bar", "bar")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				header := make(http.Header)
				header.Set("X-Bar", "bar")
				header.Set("X-Foo", "foo")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			expectEqual: true,
		},
		"different header name": {
			cachebuilder1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "value")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				header := make(http.Header)
				header.Set("X-Bar", "value")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
		},
		"different header value": {
			cachebuilder1: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "foo")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				header := make(http.Header)
				header.Set("X-Foo", "bar")

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
		},
		"header value boundaries are preserved": {
			cachebuilder1: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"a", "bc"}

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"ab", "c"}

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
		},
		"header value order is preserved": {
			cachebuilder1: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"foo", "bar"}

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
			cachebuilder2: func() string {
				header := make(http.Header)
				header["X-Foo"] = []string{"bar", "foo"}

				builder := New("test")
				builder.WriteHeader(header)

				return builder.SumString()
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			builder1 := tc.cachebuilder1()
			builder2 := tc.cachebuilder2()

			// THEN
			if tc.expectEqual {
				assert.Equal(t, builder1, builder2)
			} else {
				assert.NotEqual(t, builder1, builder2)
			}
		})
	}
}
