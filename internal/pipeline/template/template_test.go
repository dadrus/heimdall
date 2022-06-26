package template_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
)

func TestTemplate(t *testing.T) {
	t.Parallel()

	ctx := &mocks.MockContext{}
	ctx.On("RequestMethod").Return("PATCH")
	ctx.On("RequestURL").Return(&url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"})
	ctx.On("RequestHeaders").Return(map[string]string{
		"Accept":      "application/json",
		"X-My-Header": "my-value",
	})
	ctx.On("RequestHeader", "X-My-Header").Return("my-value")
	ctx.On("RequestCookie", "session_cookie").Return("session-value")
	ctx.On("RequestQueryParameter", "my_query_param").Return("query_value")
	ctx.On("RequestURL").Return(&url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"})
	ctx.On("RequestClientIPs").Return([]string{"192.168.1.1"})

	sub := &subject.Subject{
		ID: "foo",
		Attributes: map[string]any{
			"name":    "bar",
			"email":   "foo@bar.baz",
			"complex": []string{"test1", "test2"},
		},
	}

	tpl := template.Template(`{
"subject_id": {{ quote .Subject.ID }},
"name": {{ quote .Subject.Attributes.name }},
"email": {{ quote .Subject.Attributes.email }},
"complex": "{{ range $i, $el := .Subject.Attributes.complex -}}{{ if $i }} {{ end }}{{ $el }}{{ end }}",
"request_url": {{ quote .RequestURL }},
"request_method": {{ quote .RequestMethod }},
"my_header": {{ .RequestHeader "X-My-Header" | quote }},
"header_count": {{ len .RequestHeaders }},
"my_cookie": {{ .RequestCookie "session_cookie" | quote }},
"my_query_param": {{ .RequestQueryParameter "my_query_param" | quote }},
"ips": "{{ range $i, $el := .RequestClientIPs -}}{{ if $i }} {{ end }}{{ $el }}{{ end }}"
}`)

	res, err := tpl.Render(ctx, sub)
	require.NoError(t, err)

	assert.JSONEq(t, `{
"subject_id": "foo",
"name": "bar",
"email": "foo@bar.baz",
"complex": "test1 test2",
"request_url": "http://foobar.baz/zab",
"request_method": "PATCH",
"my_header": "my-value",
"header_count": 2,
"my_cookie": "session-value",
"my_query_param": "query_value",
"ips": "192.168.1.1"
}`, res)
}
