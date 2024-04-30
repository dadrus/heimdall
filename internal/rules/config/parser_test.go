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
		assert      func(t *testing.T, err error, ruleSet *RuleSet)
	}{
		{
			uc:          "unsupported content type and not empty contents",
			contentType: "foobar",
			content:     []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported 'foobar'")
			},
		},
		{
			uc:          "unsupported content type and empty contents",
			contentType: "foobar",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "Empty JSON content",
			contentType: "application/json",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set without rules",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": []
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules' must contain more than 0 items")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule without required elements",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [{"forward_to": {"host":"foo.bar"}}]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'id' is a required field")
				require.Contains(t, err.Error(), "'rules'[0].'match' is a required field")
				require.Contains(t, err.Error(), "'rules'[0].'execute' must contain more than 0 items")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule which match definition does not contain required fields",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [{"id": "foo", "match":{"with": {"host_glob":"**"}}, "execute": [{"authenticator":"test"}]}]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'match'.'path' is a required field")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule which match definition contains conflicting fields for host matching",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar", "with": {"host_glob":"**", "host_regex":"**"}},
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'match'.'with'.'host_glob' is an excluded field")
				require.Contains(t, err.Error(), "'rules'[0].'match'.'with'.'host_regex' is an excluded field")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule which match definition contains conflicting fields for path matching",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar", "with": {"path_glob":"**", "path_regex":"**"}},
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'match'.'with'.'path_glob' is an excluded field")
				require.Contains(t, err.Error(), "'rules'[0].'match'.'with'.'path_regex' is an excluded field")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule which match definition contains unsupported scheme",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar", "with": {"scheme":"foo", "methods":["ALL"]}},
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'match'.'with'.'scheme' must be one of [http https]")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with a rule with forward_to without host",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar"},
    "execute": [{"authenticator":"test"}],
    "forward_to": { "rewrite": {"scheme": "http"}}
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'forward_to'.'host' is a required field")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with invalid allow_encoded_slashes settings",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar"},
    "allow_encoded_slashes": "foo",
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'allow_encoded_slashes' must be one of [off on no_decode]")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "JSON rule set with invalid backtracking_enabled settings",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar", "backtracking_enabled": true },
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'backtracking_enabled' is an excluded field")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "Valid JSON rule set",
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{"path":"/foo/bar", "with": { "methods": ["ALL"] }, "backtracking_enabled": true },
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleSet)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Equal(t, "foo", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rul := ruleSet.Rules[0]
				require.NotNil(t, rul)
				assert.Equal(t, "foo", rul.ID)
				assert.Equal(t, "/foo/bar", rul.Matcher.Path)
				assert.ElementsMatch(t, []string{"ALL"}, rul.Matcher.With.Methods)
				assert.Len(t, rul.Execute, 1)
				assert.Equal(t, "test", rul.Execute[0]["authenticator"])
			},
		},
		{
			uc:          "Valid YAML rule set",
			contentType: "application/yaml",
			content: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    path: /foo/bar
    with:
      methods:
        - GET
  forward_to:
    host: test
  allow_encoded_slashes: no_decode
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleSet)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Equal(t, "foo", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)
				rul := ruleSet.Rules[0]
				require.NotNil(t, rul)
				assert.Equal(t, "bar", rul.ID)
				assert.Equal(t, "/foo/bar", rul.Matcher.Path)
				assert.ElementsMatch(t, []string{"GET"}, rul.Matcher.With.Methods)
				assert.Equal(t, EncodedSlashesOnNoDecode, rul.EncodedSlashesHandling)
				assert.Len(t, rul.Execute, 1)
				assert.Equal(t, "test", rul.Execute[0]["authenticator"])
			},
		},
		{
			uc:          "YAML content type and validation error",
			contentType: "application/yaml",
			content: []byte(`
version: "1"
name: foo
rules:
- id: bar
  allow_encoded_slashes: foo
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:          "YAML content and empty contents",
			contentType: "application/yaml",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			rules, err := ParseRules(tc.contentType, bytes.NewBuffer(tc.content), false)

			// THEN
			tc.assert(t, err, rules)
		})
	}
}

func TestParseYAML(t *testing.T) {
	t.Setenv("FOO", "bar")

	for _, tc := range []struct {
		uc           string
		conf         []byte
		envSupported bool
		assert       func(t *testing.T, err error, ruleSet *RuleSet)
	}{
		{
			uc: "empty rule set spec",
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
			},
		},
		{
			uc:   "invalid rule set spec",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc: "valid rule set spec without env usage",
			conf: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    path: foo
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleSet)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Equal(t, "foo", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rul := ruleSet.Rules[0]
				require.NotNil(t, rul)
				assert.Equal(t, "bar", rul.ID)
				assert.Equal(t, "foo", rul.Matcher.Path)
			},
		},
		{
			uc:           "valid rule set spec with invalid env spec",
			envSupported: true,
			conf: []byte(`
version: "1"
name: ${FOO
rules:
- id: bar
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "evaluate env")
				require.Nil(t, ruleSet)
			},
		},
		{
			uc:           "valid rule set spec with valid env usage",
			envSupported: true,
			conf: []byte(`
version: "1"
name: ${FOO}
rules:
- id: bar
  match:
    path: foo
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleSet)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Equal(t, "bar", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rul := ruleSet.Rules[0]
				require.NotNil(t, rul)
				assert.Equal(t, "bar", rul.ID)
				assert.Equal(t, "foo", rul.Matcher.Path)
			},
		},
		{
			uc: "valid rule set spec with valid env usage, which is however not enabled",
			conf: []byte(`
version: "1"
name: ${FOO}
rules:
- id: bar
  match:
    path: foo
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleSet)
				assert.Equal(t, "1", ruleSet.Version)
				assert.Equal(t, "${FOO}", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rul := ruleSet.Rules[0]
				require.NotNil(t, rul)
				assert.Equal(t, "bar", rul.ID)
				assert.Equal(t, "foo", rul.Matcher.Path)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			ruleSet, err := parseYAML(bytes.NewBuffer(tc.conf), tc.envSupported)

			// THEN
			tc.assert(t, err, ruleSet)
		})
	}
}
