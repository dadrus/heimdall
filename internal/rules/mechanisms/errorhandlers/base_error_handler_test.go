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

package errorhandlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestNewBaseErrorHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		expression string
		error      bool
	}{
		{"true == true", false},
		{"foo == true", true},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			base, err := newBaseErrorHandler("test", tc.expression)

			if tc.error {
				require.Error(t, err)
				require.Nil(t, base)
			} else {
				require.NoError(t, err)
				require.NotNil(t, base)
				assert.Equal(t, "test", base.ID())
			}
		})
	}
}

func TestBaseErrorHandlerCanExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		expression string
		req        *heimdall.Request
		cause      error
		expect     bool
	}{
		{"type(Error) == precondition_error", nil, heimdall.ErrAuthorization, false},
		{"Request.Method == 'GET'", &heimdall.Request{Method: http.MethodGet}, heimdall.ErrArgument, true},
		{"Request.URL == 'http://foo.bar'", nil, heimdall.ErrArgument, false},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			// GIVEN
			mctx := mocks.NewContextMock(t)
			mctx.EXPECT().AppContext().Return(context.TODO())
			mctx.EXPECT().Request().Return(tc.req)

			base, err := newBaseErrorHandler("test", tc.expression)
			require.NoError(t, err)

			// WHEN
			result := base.CanExecute(mctx, tc.cause)

			// THEN
			assert.Equal(t, tc.expect, result)
		})
	}
}
