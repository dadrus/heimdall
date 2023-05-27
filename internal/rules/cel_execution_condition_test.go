package rules

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

func TestNewCelExecutionCondition(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		expression string
		err        string
	}{
		{uc: "malformed expression", expression: "foobar", err: "failed compiling"},
		{uc: "is not a bool expression", expression: "1", err: "result type error"},
		{uc: "valid expression", expression: "true"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			condition, err := newCelExecutionCondition(tc.expression)

			// THEN
			if len(tc.err) != 0 {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, condition)
				require.NotNil(t, condition.p)
			}
		})
	}
}

func TestCelExecutionConditionCanExecute(t *testing.T) {
	t.Parallel()

	sub := &subject.Subject{
		ID: "foobar",
		Attributes: map[string]any{
			"group1": []string{"admin@acme.co", "analyst@acme.co"},
			"labels": []string{"metadata", "prod", "pii"},
			"groupN": []string{"forever@acme.co"},
		},
	}

	for _, tc := range []struct {
		uc         string
		expression string
		expected   bool
	}{
		{
			uc: "complex expression evaluating to true",
			expression: `Subject.Attributes.exists(c, c.startsWith('group'))
							&& Subject.Attributes.filter(c, c.startsWith('group'))
								.all(c, Subject.Attributes[c].all(g, g.endsWith('@acme.co')))`,
			expected: true,
		},
		{
			uc:         "simple expression evaluating to false",
			expression: `Subject.ID == "anonymous" && Request.Method == "GET"`,
			expected:   false,
		},
		{
			uc:         "simple expression evaluating to true",
			expression: `Subject.ID == "foobar" && Request.Method == "GET"`,
			expected:   true,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewContextMock(t)

			ctx.EXPECT().Request().Return(&heimdall.Request{
				Method: http.MethodGet,
				URL: &url.URL{
					Scheme:   "http",
					Host:     "localhost",
					Path:     "/test",
					RawQuery: "foo=bar&baz=zab",
				},
				ClientIP: []string{"127.0.0.1", "10.10.10.10"},
			})

			condition, err := newCelExecutionCondition(tc.expression)
			require.NoError(t, err)

			// WHEN
			can, err := condition.CanExecute(ctx, sub)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expected, can)
		})
	}
}
