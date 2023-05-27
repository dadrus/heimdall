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
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func TestTemplateRender(t *testing.T) {
	t.Parallel()

	// GIVEN
	reqf := mocks.NewRequestFunctionsMock(t)
	reqf.EXPECT().Header("X-My-Header").Return("my-value")
	reqf.EXPECT().Cookie("session_cookie").Return("session-value")

	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().Request().Return(&heimdall.Request{
		RequestFunctions: reqf,
		Method:           http.MethodPatch,
		URL:              &url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab", RawQuery: "my_query_param=query_value"},
		ClientIP:         []string{"192.168.1.1"},
	})

	sub := &subject.Subject{
		ID: "foo",
		Attributes: map[string]any{
			"name":    "bar",
			"email":   "foo@bar.baz",
			"complex": []string{"test1", "test2"},
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
"ips": {{ range $i, $el := .Request.ClientIP -}}{{ if $i }} {{ end }}{{ quote $el }}{{ end }},
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
}
