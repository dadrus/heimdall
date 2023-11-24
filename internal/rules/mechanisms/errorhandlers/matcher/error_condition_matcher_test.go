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

package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestErrorConditionMatcherMatch(t *testing.T) {
	t.Parallel()

	cidrMatcher, err := NewCIDRMatcher([]string{"192.168.1.0/24"})
	require.NoError(t, err)

	for _, tc := range []struct {
		uc       string
		matcher  ErrorConditionMatcher
		setupCtx func(ctx *mocks.ContextMock)
		err      error
		matching bool
	}{
		{
			uc: "doesn't match on error only if other criteria are specified",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
				CIDR:    cidrMatcher,
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"foobar": "barfoo",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions:  fnt,
					ClientIPAddresses: []string{"192.168.10.2"},
				})
			},
			err:      heimdall.ErrConfiguration,
			matching: false,
		},
		{
			uc: "doesn't match on ip only if other criteria are specified",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
				CIDR:    cidrMatcher,
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"foobar": "barfoo",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions:  fnt,
					ClientIPAddresses: []string{"192.168.1.2"},
				})
			},
			err:      heimdall.ErrArgument,
			matching: false,
		},
		{
			uc: "doesn't match on header only if other criteria are specified",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
				CIDR:    cidrMatcher,
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"foobar": "bar",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions:  fnt,
					ClientIPAddresses: []string{"192.168.10.2"},
				})
			},
			err:      heimdall.ErrArgument,
			matching: false,
		},
		{
			uc: "doesn't match at all",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
				CIDR:    cidrMatcher,
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"foobar": "barfoo",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions:  fnt,
					ClientIPAddresses: []string{"192.168.10.2"},
				})
			},
			err:      heimdall.ErrArgument,
			matching: false,
		},
		{
			uc: "matches having all matchers defined",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
				CIDR:    cidrMatcher,
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"Foobar": "bar",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions:  fnt,
					ClientIPAddresses: []string{"192.168.1.2"},
				})
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc: "matches having only error matcher defined",
			matcher: ErrorConditionMatcher{
				Error: func() *ErrorMatcher {
					errMatcher := ErrorMatcher([]ErrorDescriptor{
						{Errors: []error{heimdall.ErrConfiguration}},
					})

					return &errMatcher
				}(),
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
		{
			uc: "matches having only header matcher defined",
			matcher: ErrorConditionMatcher{
				Headers: &HeaderMatcher{"foobar": {"bar", "foo"}},
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Headers().Return(map[string]string{
					"Foobar": "bar",
				})

				ctx.EXPECT().Request().Return(&heimdall.Request{
					RequestFunctions: fnt,
				})
			},
			err:      heimdall.ErrArgument,
			matching: true,
		},
		{
			uc: "matches having only cidr matcher defined",
			matcher: ErrorConditionMatcher{
				CIDR: cidrMatcher,
			},
			setupCtx: func(ctx *mocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{
					ClientIPAddresses: []string{"192.168.1.2"},
				})
			},
			err:      heimdall.ErrConfiguration,
			matching: true,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := mocks.NewContextMock(t)
			tc.setupCtx(ctx)

			// WHEN
			matched := tc.matcher.Match(ctx, tc.err)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
