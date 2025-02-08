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

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestParseRules(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentType string
		content     []byte
		assert      func(t *testing.T, err error, ruleSet *RuleSet)
	}{
		"unsupported content type and not empty contents": {
			contentType: "foobar",
			content:     []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported 'foobar'")
			},
		},
		"unsupported content type and empty contents": {
			contentType: "foobar",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
		"empty json content": {
			contentType: "application/json",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
		"json rule set without rules": {
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
		"json rule set with a rule without required elements": {
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
		"json rule set with a rule which match definition does not contain required fields": {
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match": {
      "hosts":[{ "value": "*.foo.bar", "type": "glob" }]
    },
    "execute": [{"authenticator":"test"}]}]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'rules'[0].'match'.'routes' is a required field")
				require.Nil(t, ruleSet)
			},
		},
		"json rule set with a rule which match definition contains unsupported scheme": {
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{
      "routes": [{ "path":"/foo/bar" }],
      "scheme":"foo",
      "methods":["ALL"]
    },
    "execute": [{"authenticator":"test"}]
  }]
}`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.Contains(t, err.Error(), "'rules'[0].'match'.'scheme' must be one of [http https]")
				require.Nil(t, ruleSet)
			},
		},
		"json rule set with a rule with forward_to without host": {
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{
      "routes": [{ "path":"/foo/bar" }]
    },
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
		"json rule set with invalid allow_encoded_slashes settings": {
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{
      "routes": [{ "path":"/foo/bar" }]
    },
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
		"valid json rule set": {
			contentType: "application/json",
			content: []byte(`{
"version": "1",
"name": "foo",
"rules": [
  {
    "id": "foo",
    "match":{
      "routes": [{ "path":"/foo/bar" }],
      "methods": ["ALL"],
      "backtracking_enabled": true,
      "hosts":[{ "value": "*.foo.bar", "type": "glob" }],
      "scheme": "https"
    },
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "/foo/bar", rul.Matcher.Routes[0].Path)
				assert.ElementsMatch(t, []string{"ALL"}, rul.Matcher.Methods)
				assert.True(t, *rul.Matcher.BacktrackingEnabled)
				assert.Len(t, rul.Execute, 1)
				assert.Equal(t, "test", rul.Execute[0]["authenticator"])
			},
		},
		"valid yaml rule set": {
			contentType: "application/yaml",
			content: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    routes:
      - path: /foo/:bar
        path_params:
          - name: bar
            type: glob
            value: "*foo"
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "/foo/:bar", rul.Matcher.Routes[0].Path)
				assert.Len(t, rul.Matcher.Routes[0].PathParams, 1)
				assert.ElementsMatch(t, []string{"GET"}, rul.Matcher.Methods)
				assert.Equal(t, "test", rul.Backend.Host)
				assert.Equal(t, EncodedSlashesOnNoDecode, rul.EncodedSlashesHandling)
				assert.Len(t, rul.Execute, 1)
				assert.Equal(t, "test", rul.Execute[0]["authenticator"])
			},
		},
		"yaml content type and validation error due to missing properties": {
			contentType: "application/yaml",
			content: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    routes:
      - path: /foo/:*
        path_params:
          - name: "*"
            type: glob
            value: "*foo"
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'rules'[0].'match'.'routes'[0].'path_params'[0].'name' should not be equal to *")
				require.Nil(t, ruleSet)
			},
		},
		"yaml content type and validation error due bad path params name": {
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

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'rules'[0].'allow_encoded_slashes' must be one of [off on no_decode]")
				require.ErrorContains(t, err, "'rules'[0].'match' is a required field")
				require.ErrorContains(t, err, "'rules'[0].'execute' must contain more than 0 items")
				require.Nil(t, ruleSet)
			},
		},
		"yaml content and empty contents": {
			contentType: "application/yaml",
			assert: func(t *testing.T, err error, ruleSet *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
				require.Nil(t, ruleSet)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			// WHEN
			rules, err := ParseRules(appCtx, tc.contentType, bytes.NewBuffer(tc.content), false)

			// THEN
			tc.assert(t, err, rules)
			appCtx.AssertExpectations(t)
		})
	}
}

func TestParseYAML(t *testing.T) {
	t.Setenv("FOO", "bar")

	for uc, tc := range map[string]struct {
		conf               []byte
		envSupported       bool
		enforceUpstreamTLS bool
		assert             func(t *testing.T, err error, ruleSet *RuleSet)
	}{
		"empty rule set spec": {
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.ErrorIs(t, err, ErrEmptyRuleSet)
			},
		},
		"invalid rule set spec": {
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.Error(t, err)
			},
		},
		"valid rule set spec without env usage": {
			conf: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    routes:
      - path: foo
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "foo", rul.Matcher.Routes[0].Path)
			},
		},
		"valid rule set spec with invalid env spec": {
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
		"valid rule set spec with valid env usage": {
			envSupported: true,
			conf: []byte(`
version: "1"
name: ${FOO}
rules:
- id: bar
  match:
    routes:
      - path: /foo/:bar
        path_params:
          - name: bar
            type: glob
            value: "[a-z]"
    methods:
      - GET
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "/foo/:bar", rul.Matcher.Routes[0].Path)
				assert.Len(t, rul.Matcher.Routes[0].PathParams, 1)
				assert.Equal(t, "bar", rul.Matcher.Routes[0].PathParams[0].Name)
				assert.Equal(t, "glob", rul.Matcher.Routes[0].PathParams[0].Type)
				assert.Equal(t, "[a-z]", rul.Matcher.Routes[0].PathParams[0].Value)
				assert.Equal(t, "GET", rul.Matcher.Methods[0])
			},
		},
		"valid rule set spec with valid env usage, which is however not enabled": {
			conf: []byte(`
version: "1"
name: ${FOO}
rules:
- id: bar
  match:
    routes:
      - path: foo
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "foo", rul.Matcher.Routes[0].Path)
			},
		},
		"enforced but disable TLS for upstream communication": {
			enforceUpstreamTLS: true,
			conf: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    routes:
      - path: foo
  forward_to:
    host: foo.bar
    rewrite:
      scheme: http
  execute:
    - authenticator: test
`),
			assert: func(t *testing.T, err error, _ *RuleSet) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "'rules'[0].'forward_to'.'rewrite'.'scheme' must be https")
			},
		},
		"valid ruleset with disabled and not enforced TLS for upstream communication": {
			conf: []byte(`
version: "1"
name: foo
rules:
- id: bar
  match:
    routes:
      - path: foo
  forward_to:
    host: foo.bar
    rewrite:
      scheme: http
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
				assert.Len(t, rul.Matcher.Routes, 1)
				assert.Equal(t, "foo", rul.Matcher.Routes[0].Path)

				be := rul.Backend
				require.NotNil(t, be)
				assert.Equal(t, "foo.bar", be.Host)

				urlRewriter := be.URLRewriter
				require.NotNil(t, urlRewriter)
				assert.Equal(t, "http", urlRewriter.Scheme)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			es := config.EnforcementSettings{EnforceUpstreamTLS: tc.enforceUpstreamTLS}

			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)

			// WHEN
			ruleSet, err := parseYAML(appCtx, bytes.NewBuffer(tc.conf), tc.envSupported)

			// THEN
			tc.assert(t, err, ruleSet)
			appCtx.AssertExpectations(t)
		})
	}
}
