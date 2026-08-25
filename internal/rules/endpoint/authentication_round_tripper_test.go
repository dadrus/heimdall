// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package endpoint

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint/mocks"
)

func TestAuthenticationRoundTripperRoundTrip(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		configureStrategy func(t *testing.T, strategy *mocks.AuthenticationStrategyMock)
		configureNext     func(t *testing.T, next *RoundTripperMock, req *http.Request)
		assert            func(t *testing.T, response *http.Response, err error, req *http.Request)
	}{
		"successful": {
			configureStrategy: func(t *testing.T, strategy *mocks.AuthenticationStrategyMock) {
				t.Helper()

				strategy.EXPECT().
					Apply(mock.MatchedBy(func(req *http.Request) bool {
						req.Method = http.MethodPatch

						return true
					})).
					Return(nil)
			},
			configureNext: func(t *testing.T, next *RoundTripperMock, req *http.Request) {
				t.Helper()

				next.EXPECT().
					RoundTrip(mock.MatchedBy(func(actual *http.Request) bool {
						assert.NotSame(t, req, actual)
						assert.Equal(t, http.MethodPatch, actual.Method)
						assert.Equal(t, req.Context(), actual.Context())

						return true
					})).
					Return(&http.Response{StatusCode: http.StatusOK}, nil)
			},
			assert: func(t *testing.T, response *http.Response, err error, req *http.Request) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, http.StatusOK, response.StatusCode)

				// Applying authentication to the shallow copy must not modify
				// fields stored directly on the original request.
				assert.Equal(t, http.MethodGet, req.Method)
			},
		},
		"failed authentication": {
			configureStrategy: func(t *testing.T, strategy *mocks.AuthenticationStrategyMock) {
				t.Helper()

				strategy.EXPECT().
					Apply(mock.Anything).
					Return(errors.New("test error"))
			},
			assert: func(t *testing.T, response *http.Response, err error, _ *http.Request) {
				t.Helper()

				assert.Nil(t, response)
				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrInternal)
				require.ErrorContains(t, err, "failed to authenticate request")
				require.ErrorContains(t, err, "test error")
			},
		},
		"failed round trip": {
			configureStrategy: func(t *testing.T, strategy *mocks.AuthenticationStrategyMock) {
				t.Helper()

				strategy.EXPECT().
					Apply(mock.Anything).
					Return(nil)
			},
			configureNext: func(t *testing.T, next *RoundTripperMock, _ *http.Request) {
				t.Helper()

				next.EXPECT().
					RoundTrip(mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, response *http.Response, err error, _ *http.Request) {
				t.Helper()

				assert.Nil(t, response)
				require.EqualError(t, err, "test error")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://example.com",
				nil,
			)
			require.NoError(t, err)

			strategy := mocks.NewAuthenticationStrategyMock(t)
			tc.configureStrategy(t, strategy)

			next := NewRoundTripperMock(t)
			if tc.configureNext != nil {
				tc.configureNext(t, next, req)
			}

			rt := &authenticationRoundTripper{
				next:     next,
				strategy: strategy,
			}

			// WHEN
			response, err := rt.RoundTrip(req) //nolint:bodyclose

			// THEN
			tc.assert(t, response, err, req)
		})
	}
}
