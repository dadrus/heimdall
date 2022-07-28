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

func TestScriptExecuteOnSubject(t *testing.T) {
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

func TestScriptExecuteOnPayload(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	for _, tc := range []struct {
		uc      string
		script  string
		payload []byte
		assert  func(t *testing.T, err error, result script.Result)
	}{
		{
			uc:      "simple payload is checked by script",
			payload: []byte(`{ "result": true }`),
			script:  `heimdall.Payload.result === true`,
			assert: func(t *testing.T, err error, result script.Result) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, result.ToBoolean())
			},
		},
		{
			uc:      "script raises exception",
			payload: []byte(`{ "result": true }`),
			script: `
if (heimdall.Payload.result === true) {
  throw "result is true"
}`,
			assert: func(t *testing.T, err error, result script.Result) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "result is true")
			},
		},
		{
			uc:      "script checks more complex payload",
			payload: []byte(`{ "result": ["foo", "bar"] }`),
			script: `
var groups = heimdall.Payload.result
if (groups.includes("foo")) {
  true
} else {
  false
}`,
			assert: func(t *testing.T, err error, result script.Result) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, result.ToBoolean())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ecmaScript, err := script.New(tc.script)
			require.NoError(t, err)

			var payload map[string]any
			err = json.Unmarshal(tc.payload, &payload)
			require.NoError(t, err)

			// WHEN
			res, err := ecmaScript.ExecuteOnPayload(ctx, payload)

			// THEN
			tc.assert(t, err, res)
		})
	}

	ecmaScript, err := script.New(`heimdall.Payload.result === true`)
	require.NoError(t, err)

	// WHEN
	res, err := ecmaScript.ExecuteOnPayload(ctx, map[string]any{"result": true})

	// THEN
	require.NoError(t, err)

	assert.True(t, res.ToBoolean())
}
