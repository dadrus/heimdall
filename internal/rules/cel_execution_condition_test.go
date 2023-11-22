// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type idProvider struct {
	id string
}

func (i idProvider) ID() string { return i.id }

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
		{
			uc:         "expression acting on an error evaluating to true",
			expression: `Error.Is(authorization_error) && Error.Is(precondition_error) && Error.Source() == "test"`,
			expected:   true,
		},
		{
			uc:         "expression acting on client ip addresses",
			expression: `network("10.10.10.0/24").Contains(Request.ClientIP[1])`,
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

			causeErr := errorchain.New(heimdall.ErrAuthorization).
				CausedBy(errorchain.New(heimdall.ErrArgument)).
				WithErrorContext(idProvider{"test"})

			condition, err := newCelExecutionCondition(tc.expression)
			require.NoError(t, err)

			// WHEN
			can, err := condition.CanExecute(ctx, sub, causeErr)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expected, can)
		})
	}
}
