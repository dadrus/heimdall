package template_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func TestTemplateRender(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("RequestMethod").Return("PATCH")
	ctx.On("RequestHeader", "X-My-Header").Return("my-value")
	ctx.On("RequestCookie", "session_cookie").Return("session-value")
	ctx.On("RequestURL").Return(
		&url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab", RawQuery: "my_query_param=query_value"})
	ctx.On("RequestClientIPs").Return([]string{"192.168.1.1"})

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
"ips": "{{ range $i, $el := .Request.ClientIP -}}{{ if $i }} {{ end }}{{ $el }}{{ end }}"
}`)
	require.NoError(t, err)

	// WHEN
	res, err := tpl.Render(ctx, sub)

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
"ips": "192.168.1.1"
}`, res)
}
