// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package radixtree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReverseHost(t *testing.T) {
	t.Parallel()

	for uc, values := range map[string][]string{
		"localhost":         {"localhost", "localhost"},
		"example.com":       {"example.com", "com.example"},
		"*.example.com":     {"*.example.com", "com.example.*"},
		"*.foo.example.com": {"*.foo.example.com", "com.example.foo.*"},
		"*":                 {"*", "*"},
		"127.0.0.1":         {"127.0.0.1", "1.0.0.127"},
	} {
		t.Run(uc, func(t *testing.T) {
			result := reverseHost(values[0])

			assert.Equal(t, values[1], result)
		})
	}
}

func BenchmarkReverseHost(b *testing.B) {
	for uc, values := range map[string][]string{
		"localhost":         {"localhost", "localhost"},
		"example.com":       {"example.com", "com.example"},
		"*.example.com":     {"*.example.com", "com.example.*"},
		"*.foo.example.com": {"*.foo.example.com", "com.example.foo.*"},
		"*":                 {"*", "*"},
		"127.0.0.1":         {"127.0.0.1", "1.0.0.127"},
	} {
		b.Run(uc, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for range b.N {
				reverseHost(values[0])
			}
		})
	}
}
