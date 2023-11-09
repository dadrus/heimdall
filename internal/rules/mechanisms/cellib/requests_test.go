package cellib

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestRequests(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(
		cel.Variable("req", cel.DynType),
		Requests(),
		Urls(),
	)
	require.NoError(t, err)

	rawURI := "http://localhost/foo/bar?foo=bar&foo=baz&bar=foo"
	uri, err := url.Parse("http://localhost/foo/bar?foo=bar&foo=baz&bar=foo")
	require.NoError(t, err)

	reqf := mocks.NewRequestFunctionsMock(t)
	reqf.EXPECT().Cookie("foo").Return("bar")
	reqf.EXPECT().Header("bar").Return("baz")

	req := &heimdall.Request{
		RequestFunctions: reqf,
		Method:           http.MethodHead,
		URL:              uri,
		ClientIP:         []string{"1.1.1.1"},
	}

	for _, tc := range []struct {
		expr string
	}{
		{expr: `req.Method == "HEAD"`},
		{expr: `req.URL.String() == "` + rawURI + `"`},
		{expr: `req.Cookie("foo") == "bar"`},
		{expr: `req.Header("bar") == "baz"`},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			ast, iss := env.Compile(tc.expr)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			ast, iss = env.Check(ast)
			if iss != nil {
				require.NoError(t, iss.Err())
			}

			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			out, _, err := prg.Eval(map[string]any{"req": req})
			require.NoError(t, err)
			require.Equal(t, true, out.Value()) //nolint:testifylint
		})
	}
}
