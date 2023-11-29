// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package httpx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		host  string
		port  int
	}{
		{value: "", host: "", port: -1},
		{value: "[:0]:90", host: ":0", port: 90},
		{value: "127.0.0.1:foo", host: "127.0.0.1", port: -1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			// WHEN
			host, port := HostPort(tc.value)

			// THEN
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
		})
	}
}
