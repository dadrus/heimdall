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

func TestNewCelExecutionCondition(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		expression string
		err        string
	}{
		"malformed expression":     {expression: "foobar", err: "failed compiling"},
		"is not a bool expression": {expression: "1", err: "result type error"},
		"valid expression":         {expression: "true"},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			condition, err := newCelExecutionCondition(tc.expression)

			// THEN
			if len(tc.err) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, condition)
				require.NotNil(t, condition.e)
			}
		})
	}
}

func TestCelExecutionConditionCanExecuteOnSubject(t *testing.T) {
	t.Parallel()

	sub := &subject.Subject{
		ID: "foobar",
		Attributes: map[string]any{
			"group1": []string{"admin@acme.co", "analyst@acme.co"},
			"labels": []string{"metadata", "prod", "pii"},
			"groupN": []string{"forever@acme.co"},
		},
	}

	for uc, tc := range map[string]struct {
		expression string
		expected   bool
	}{
		"complex expression evaluating to true": {
			expression: `Subject.Attributes.exists(c, c.startsWith('group'))
							&& Subject.Attributes.filter(c, c.startsWith('group'))
								.all(c, Subject.Attributes[c].all(g, g.endsWith('@acme.co')))`,
			expected: true,
		},
		"simple expression evaluating to false": {
			expression: `Subject.ID == "anonymous" && Request.Method == "GET"`,
			expected:   false,
		},
		"simple expression evaluating to true": {
			expression: `Subject.ID == "foobar" && Request.Method == "GET"`,
			expected:   true,
		},
		"expression acting on client ip addresses": {
			expression: `Request.ClientIPAddresses[1] in networks("10.10.10.0/24")`,
			expected:   true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewRequestContextMock(t)

			ctx.EXPECT().Request().Return(&heimdall.Request{
				Method: http.MethodGet,
				URL: &heimdall.URL{URL: url.URL{
					Scheme:   "http",
					Host:     "localhost",
					Path:     "/test",
					RawQuery: "foo=bar&baz=zab",
				}},
				ClientIPAddresses: []string{"127.0.0.1", "10.10.10.10"},
			})

			condition, err := newCelExecutionCondition(tc.expression)
			require.NoError(t, err)

			// WHEN
			can, err := condition.CanExecuteOnSubject(ctx, sub)

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expected, can)
		})
	}
}

type testIdentifier string

func (tid testIdentifier) ID() string   { return string(tid) }
func (tid testIdentifier) Name() string { return string(tid) }

func TestCelExecutionConditionCanExecuteOnError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		expression string
		expected   bool
	}{
		"complex expression evaluating to true": {
			expression: `type(Error) in [communication_error, authorization_error] && 
                           Error.Source == "foobar" && Error.StepID == "foobar" &&
                           "bar" in Request.URL.Query().foo`,
			expected: true,
		},
		"simple expression evaluating to false": {
			expression: `type(Error) == internal_error && Request.Method == "GET"`,
			expected:   false,
		},
		"simple expression evaluating to true": {
			expression: `type(Error) == authorization_error && Request.Method == "GET"`,
			expected:   true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewRequestContextMock(t)

			ctx.EXPECT().Request().Return(&heimdall.Request{
				Method: http.MethodGet,
				URL: &heimdall.URL{URL: url.URL{
					Scheme:   "http",
					Host:     "localhost",
					Path:     "/test",
					RawQuery: "foo=bar&baz=zab",
				}},
				ClientIPAddresses: []string{"127.0.0.1", "10.10.10.10"},
			})

			condition, err := newCelExecutionCondition(tc.expression)
			require.NoError(t, err)

			// WHEN
			can, err := condition.CanExecuteOnError(ctx, errorchain.
				NewWithMessage(heimdall.ErrCommunication, "test").
				CausedBy(heimdall.ErrAuthorization).WithErrorContext(testIdentifier("foobar")))

			// THEN
			require.NoError(t, err)
			assert.Equal(t, tc.expected, can)
		})
	}
}
