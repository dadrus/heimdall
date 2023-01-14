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

package rule

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestParseRules(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		contentType string
		content     []byte
		assert      func(t *testing.T, err error, rules []Configuration)
	}{
		{
			uc:          "unsupported content type and not empty contents",
			contentType: "foobar",
			content:     []byte(`foo: bar`),
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported 'foobar'")
			},
		},
		{
			uc:          "unsupported content type and empty contents",
			contentType: "foobar",
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
		{
			uc:          "JSON content and not empty contents",
			contentType: "application/json",
			content:     []byte(`[{"id": "bar"}]`),
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:          "JSON content and empty contents",
			contentType: "application/json",
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
		{
			uc:          "YAML content and not empty contents",
			contentType: "application/yaml",
			content:     []byte(`- id: bar`),
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:          "YAML content and empty contents",
			contentType: "application/yaml",
			assert: func(t *testing.T, err error, rules []Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			rules, err := ParseRules(tc.contentType, bytes.NewBuffer(tc.content))

			// THEN
			tc.assert(t, err, rules)
		})
	}
}

func TestParseYAML(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, ruleSet []Configuration)
	}{
		{
			uc: "empty rule set spec",
			assert: func(t *testing.T, err error, ruleSet []Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSet)
			},
		},
		{
			uc:   "invalid rule set spec",
			conf: []byte(`- foo: bar`),
			assert: func(t *testing.T, err error, ruleSet []Configuration) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "valid rule set spec",
			conf: []byte(`- id: bar`),
			assert: func(t *testing.T, err error, ruleSet []Configuration) {
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
