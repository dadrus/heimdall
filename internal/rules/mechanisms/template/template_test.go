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

package template_test

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		raw    string
		opts   []template.Option
		assert func(t *testing.T, tpl template.Template, err error)
	}{
		"creates template": {
			raw: `hello {{ .Name }}`,
			assert: func(t *testing.T, tpl template.Template, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, tpl)
				assert.Equal(t, `hello {{ .Name }}`, tpl.String())
			},
		},
		"returns configuration error for malformed template": {
			raw: `hello {{ .Name `,
			assert: func(t *testing.T, tpl template.Template, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `template: Heimdall`)
				require.Nil(t, tpl)
			},
		},
		"does not expose env function": {
			raw: `{{ env "HOME" }}`,
			assert: func(t *testing.T, tpl template.Template, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `function "env" not defined`)
				require.Nil(t, tpl)
			},
		},
		"does not expose expandenv function": {
			raw: `{{ expandenv "$HOME" }}`,
			assert: func(t *testing.T, tpl template.Template, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `function "expandenv" not defined`)
				require.Nil(t, tpl)
			},
		},
		"uses configured template name in parse error": {
			raw: `hello {{ .Name `,
			opts: []template.Option{
				template.WithName("test-template"),
			},
			assert: func(t *testing.T, tpl template.Template, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, `template: test-template`)
				require.Nil(t, tpl)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tpl, err := template.New(tc.raw, tc.opts...)

			tc.assert(t, tpl, err)
		})
	}
}

func TestMust(t *testing.T) {
	t.Parallel()

	t.Run("returns template", func(t *testing.T) {
		t.Parallel()

		tpl := template.Must(`hello {{ .Name }}`)

		require.NotNil(t, tpl)

		res, err := tpl.Render(map[string]any{"Name": "heimdall"})
		require.NoError(t, err)
		assert.Equal(t, "hello heimdall", res)
	})

	t.Run("panics on invalid template", func(t *testing.T) {
		t.Parallel()

		require.Panics(t, func() {
			template.Must(`hello {{ .Name `)
		})
	})
}

func TestTemplateRender(t *testing.T) {
	t.Parallel()

	t.Run("renders template", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		reqf := mocks.NewRequestFunctionsMock(t)
		reqf.EXPECT().Header("X-My-Header").Return("my-value")
		reqf.EXPECT().Cookie("session_cookie").Return("session-value")

		ctx := mocks.NewContextMock(t)
		ctx.EXPECT().Request().Return(&pipeline.Request{
			RequestFunctions: reqf,
			Method:           http.MethodPatch,
			URL: &pipeline.URL{
				URL: url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab", RawQuery: "my_query_param=query_value"},
			},
			ClientIPAddresses: []string{"192.168.1.1"},
		})

		sub := pipeline.Subject{
			"default": &pipeline.Principal{
				ID: "foo",
				Attributes: map[string]any{
					"name":    "bar",
					"email":   "foo@bar.baz",
					"complex": []string{"test1", "test2"},
				},
			},
		}

		tpl, err := template.New(`{
"subject_id": {{ quote .Subject.ID }},
"name": {{ quote .Subject.Attributes.name }},
"email": {{ quote .Subject.Attributes.email }},
"complex": "{{ range $i, $el := .Subject.Attributes.complex -}}{{ if $i }} {{ end }}{{ $el }}{{ end }}",
"request_url": {{ quote .Request.URL }},
"request_method": {{ quote .Request.Method }},
"my_header": {{ .Request.Header "X-My-Header" | quote }},
"my_cookie": {{ .Request.Cookie "session_cookie" | quote }},
"my_query_param": {{ index .Request.URL.Query.my_query_param 0 | quote }},
"ips": {{ range $i, $el := .Request.ClientIPAddresses -}}{{ if $i }} {{ end }}{{ quote $el }}{{ end }},
"values": [{{ quote .Values.key1 }}, {{ quote .Values.key2 }}]
}`)
		require.NoError(t, err)

		// WHEN
		res, err := tpl.Render(map[string]any{
			"Request": ctx.Request(),
			"Subject": sub,
			"Values":  map[string]string{"key1": "foo", "key2": "bar"},
		})

		// THEN
		require.NoError(t, err)

		assert.JSONEq(t, `{
"subject_id": "foo",
"name": "bar",
"email": "foo@bar.baz",
"complex": "test1 test2",
"request_url": "http://foobar.baz/zab?my_query_param=query_value",
"request_method": "PATCH",
"my_header": "my-value",
"my_cookie": "session-value",
"my_query_param": "query_value",
"ips": "192.168.1.1",
"values": ["foo", "bar"]
}`, res)
	})

	t.Run("returns render error", func(t *testing.T) {
		t.Parallel()

		tpl, err := template.New(`{{ atIndex 2 .Values }}`)
		require.NoError(t, err)

		value, err := tpl.Render(map[string]any{
			"Values": []string{"a"},
		})

		require.Error(t, err)
		require.ErrorIs(t, err, template.ErrTemplateRender)
		require.ErrorContains(t, err, "position is outside of the list boundaries")
		assert.Empty(t, value)
	})
}

func TestTemplateHash(t *testing.T) {
	t.Parallel()

	raw := `hello {{ .Name }}`
	expected := sha256.Sum256([]byte(raw))

	tpl, err := template.New(raw)
	require.NoError(t, err)

	assert.Equal(t, expected[:], tpl.Hash())
}

func TestTemplateString(t *testing.T) {
	t.Parallel()

	raw := `hello {{ .Name }}`

	tpl, err := template.New(raw)
	require.NoError(t, err)

	assert.Equal(t, raw, tpl.String())
}
