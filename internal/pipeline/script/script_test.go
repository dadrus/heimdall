package script_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/script"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

func TestScriptExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())
	ctx.On("RequestMethod").Return("PATCH")
	ctx.On("RequestURL").Return(&url.URL{Scheme: "http", Host: "foobar.baz", Path: "zab"})
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

	ecmaScript, err := script.New(`
var foo = {
	"subject_id": heimdall.Subject.ID,
	"name": heimdall.Subject.Attributes.name,
	"email": heimdall.Subject.Attributes.email,
	"complex": heimdall.Subject.Attributes.complex.join(" "),
	"request_url": heimdall.RequestURL(),
	"request_method": heimdall.RequestMethod(),
	"my_header": heimdall.RequestHeader("X-My-Header"),
	"my_cookie": heimdall.RequestCookie("session_cookie"),
	"my_query_param": heimdall.RequestQueryParameter("my_query_param"),
	"ips": heimdall.RequestClientIPs().join(" ")
}

foo
`)

	require.NoError(t, err)

	// WHEN
	res, err := ecmaScript.ExecuteOnSubject(ctx, sub)

	// THEN
	require.NoError(t, err)

	rawJSON, err := json.Marshal(res)
	require.NoError(t, err)

	assert.JSONEq(t, `{
"subject_id": "foo",
"name": "bar",
"email": "foo@bar.baz",
"complex": "test1 test2",
"request_url": "http://foobar.baz/zab",
"request_method": "PATCH",
"my_header": "my-value",
"my_cookie": "session-value",
"my_query_param": "query_value",
"ips": "192.168.1.1"
}`, string(rawJSON))
}
