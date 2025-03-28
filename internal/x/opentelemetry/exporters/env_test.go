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

package exporters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvOr(t *testing.T) {
	for uc, tc := range map[string]struct {
		key          string
		defaultValue string
		setup        func(t *testing.T)
		assert       func(t *testing.T, value string)
	}{
		"no env with default": {
			key:          "does-not-exist",
			defaultValue: "foobar",
			setup:        func(t *testing.T) { t.Helper() },
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "foobar", value)
			},
		},
		"set env": {
			key:          "TestEnvOr-ExistingKey",
			defaultValue: "foobar",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("TestEnvOr-ExistingKey", "barfoo")
			},
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "barfoo", value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tc.setup(t)

			// WHEN
			value := envOr(tc.key, tc.defaultValue)

			// THEN
			tc.assert(t, value)
		})
	}
}
