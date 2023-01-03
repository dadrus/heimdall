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

package rulesetparser

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

func TestParseYAML(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, ruleSet []rule.Configuration)
	}{
		{
			uc: "empty rule set spec",
			assert: func(t *testing.T, err error, ruleSet []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSet)
			},
		},
		{
			uc:   "invalid rule set spec",
			conf: []byte(`- foo: bar`),
			assert: func(t *testing.T, err error, ruleSet []rule.Configuration) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "valid rule set spec",
			conf: []byte(`- id: bar`),
			assert: func(t *testing.T, err error, ruleSet []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ruleSet, 1)
				assert.Equal(t, "bar", ruleSet[0].ID)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			ruleSet, err := parseYAML(bytes.NewBuffer(tc.conf))

			// THEN
			tc.assert(t, err, ruleSet)
		})
	}
}
