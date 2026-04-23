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

package pipeline

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type testErrorResponseDecorator struct {
	code    int
	headers map[string][]string
	body    string
}

func (d testErrorResponseDecorator) DecorateErrorResponse(er *ErrorResponse) {
	er.Code = d.code
	er.Headers = d.headers
	er.Body = d.body
}

func TestErrorContext(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err             error
		expectedContext any
	}{
		"extracts context from errorchain": {
			err: errorchain.New(ErrAuthentication).
				WithErrorContext("test-mechanism"),
			expectedContext: "test-mechanism",
		},
		"extracts context from wrapped errorchain": {
			err: errors.Join(
				ErrInternal,
				errorchain.New(ErrAuthentication).
					WithErrorContext(map[string]string{"foo": "bar"}),
			),
			expectedContext: map[string]string{"foo": "bar"},
		},
		"returns false if no context carrier": {
			err: ErrInternal,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			context := errorContext(tc.err)
			assert.Equal(t, tc.expectedContext, context)
		})
	}
}

func TestNewResponseError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		cause            error
		input            []ErrorResponse
		expectedResponse ErrorResponse
	}{
		"without explicit response": {
			cause:            ErrInternal,
			expectedResponse: ErrorResponse{},
		},
		"with explicit response": {
			cause: ErrInternal,
			input: []ErrorResponse{{
				Code:    500,
				Headers: map[string][]string{"X-Error": {"foo"}},
				Body:    "bar",
			}},
			expectedResponse: ErrorResponse{
				Code:    500,
				Headers: map[string][]string{"X-Error": {"foo"}},
				Body:    "bar",
			},
		},
		"applies decorator from cause context": {
			cause: errorchain.New(ErrAuthentication).WithErrorContext(testErrorResponseDecorator{
				code:    401,
				headers: map[string][]string{"WWW-Authenticate": {"Basic realm=\"foo\""}},
				body:    "denied",
			}),
			input: []ErrorResponse{{
				Code:    500,
				Headers: map[string][]string{"X-Error": {"foo"}},
				Body:    "bar",
			}},
			expectedResponse: ErrorResponse{
				Code:    401,
				Headers: map[string][]string{"WWW-Authenticate": {"Basic realm=\"foo\""}},
				Body:    "denied",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			responseError := NewResponseError(tc.cause, tc.input...)

			assert.Equal(t, tc.expectedResponse, responseError.ErrorResponse)
			assert.Equal(t, tc.expectedResponse, responseError.Response())
			assert.ErrorIs(t, responseError.Cause, tc.cause)
		})
	}
}
