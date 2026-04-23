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

package errorhandler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestHandlerHandle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		handler   ErrorHandler
		err       error
		expCode   int
		accept    string
		expBody   string
		expHeader http.Header
	}{
		"authentication error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrAuthentication),
			expCode:   http.StatusUnauthorized,
			expHeader: http.Header{},
		},
		"authentication error overridden": {
			handler:   New(WithAuthenticationErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrAuthentication),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"authentication error verbose without mime type set": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrAuthentication),
			expCode:   http.StatusUnauthorized,
			expHeader: http.Header{"Content-Type": []string{"text/html"}, "X-Content-Type-Options": []string{"nosniff"}},
			expBody:   "<p>authentication error</p>",
		},
		"authorization error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrAuthorization),
			expCode:   http.StatusForbidden,
			expHeader: http.Header{},
		},
		"authorization error overridden": {
			handler:   New(WithAuthorizationErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrAuthorization),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"authorization error verbose expecting text/plain": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrAuthorization),
			expCode:   http.StatusForbidden,
			expHeader: http.Header{"Content-Type": []string{"text/plain"}, "X-Content-Type-Options": []string{"nosniff"}},
			accept:    "text/plain",
			expBody:   "authorization error: authorization error",
		},
		"communication timeout error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrCommunicationTimeout),
			expCode:   http.StatusBadGateway,
			expHeader: http.Header{},
		},
		"communication timeout error overridden": {
			handler:   New(WithCommunicationErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrCommunicationTimeout),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"communication timeout error verbose expecting application/xml": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrCommunicationTimeout),
			expCode:   http.StatusBadGateway,
			expHeader: http.Header{"Content-Type": []string{"application/xml"}, "X-Content-Type-Options": []string{"nosniff"}},
			accept:    "application/xml",
			expBody:   "<error><code>communicationTimeoutError</code><message>communication timeout error</message></error>",
		},
		"communication error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrCommunication),
			expCode:   http.StatusBadGateway,
			expHeader: http.Header{},
		},
		"communication error overridden": {
			handler:   New(WithCommunicationErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrCommunication),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"communication error verbose expecting application/json": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrCommunication),
			expCode:   http.StatusBadGateway,
			expHeader: http.Header{"Content-Type": []string{"application/json"}, "X-Content-Type-Options": []string{"nosniff"}},
			accept:    "application/json",
			expBody:   `{"code":"communicationError","message":"communication error"}`,
		},
		"precondition error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrArgument),
			expCode:   http.StatusBadRequest,
			expHeader: http.Header{},
		},
		"precondition error overridden": {
			handler:   New(WithPreconditionErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrArgument),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"precondition error verbose expecting text/html": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrArgument),
			expCode:   http.StatusBadRequest,
			expHeader: http.Header{"Content-Type": []string{"text/html"}, "X-Content-Type-Options": []string{"nosniff"}},
			expBody:   "<p>argument error</p>",
		},
		"no rule error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrNoRuleFound),
			expCode:   http.StatusNotFound,
			expHeader: http.Header{},
		},
		"no rule error overridden": {
			handler:   New(WithNoRuleErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrNoRuleFound),
			expCode:   http.StatusContinue,
			expHeader: http.Header{},
		},
		"no rule error verbose without mime type": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrNoRuleFound),
			expCode:   http.StatusNotFound,
			expHeader: http.Header{"Content-Type": []string{"text/html"}, "X-Content-Type-Options": []string{"nosniff"}},
			expBody:   "<p>no rule found</p>",
		},
		"redirect error": {
			handler:   New(),
			err:       &pipeline.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expCode:   http.StatusFound,
			expHeader: http.Header{"Location": []string{"http://foo.local"}},
		},
		"redirect error verbose without mime type": {
			handler:   New(WithVerboseErrors(true)),
			err:       &pipeline.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expCode:   http.StatusFound,
			expHeader: http.Header{"Location": []string{"http://foo.local"}},
		},
		"internal error default": {
			handler:   New(),
			err:       errorchain.New(pipeline.ErrInternal),
			expCode:   http.StatusInternalServerError,
			expHeader: http.Header{},
		},
		"internal error overridden": {
			handler:   New(WithInternalServerErrorCode(http.StatusContinue)),
			err:       errorchain.New(pipeline.ErrInternal),
			expHeader: http.Header{},
			expCode:   http.StatusContinue,
		},
		"internal error verbose without mime type": {
			handler:   New(WithVerboseErrors(true)),
			err:       errorchain.New(pipeline.ErrInternal),
			expCode:   http.StatusInternalServerError,
			expHeader: http.Header{"Content-Type": []string{"text/html"}, "X-Content-Type-Options": []string{"nosniff"}},
			expBody:   "<p>internal error</p>",
		},
		"generic error with body": {
			handler: New(),
			err: &pipeline.ResponseError{
				ErrorResponse: pipeline.ErrorResponse{
					Code:    http.StatusOK,
					Body:    `{"foo": "bar"}`,
					Headers: map[string][]string{"Content-Type": {"application/json; charset=utf-8"}},
				},
			},
			expCode:   http.StatusOK,
			expBody:   `{"foo": "bar"}`,
			expHeader: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		},
		"generic error with multiple header values": {
			handler: New(),
			err: &pipeline.ResponseError{
				ErrorResponse: pipeline.ErrorResponse{
					Code: http.StatusOK,
					Headers: map[string][]string{
						"Set-Cookie": {"a=1", "b=2"},
					},
				},
			},
			expCode:   http.StatusOK,
			expHeader: http.Header{"Set-Cookie": []string{"a=1", "b=2"}},
		},
		"generic error without body and header": {
			handler: New(),
			err: &pipeline.ResponseError{
				ErrorResponse: pipeline.ErrorResponse{
					Code: http.StatusOK,
				},
			},
			expHeader: http.Header{},
			expCode:   http.StatusOK,
		},
		"generic error verbose": {
			handler: New(WithVerboseErrors(true)),
			err: &pipeline.ResponseError{
				ErrorResponse: pipeline.ErrorResponse{
					Code:    http.StatusAccepted,
					Body:    `{"foo": "bar"}`,
					Headers: map[string][]string{"Content-Type": {"application/json; charset=utf-8"}},
				},
			},
			expCode:   http.StatusAccepted,
			expBody:   `{"foo": "bar"}`,
			expHeader: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			recorder := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if len(tc.accept) != 0 {
				req.Header.Set("Accept", tc.accept)
			}

			tc.handler.HandleError(recorder, req, tc.err)

			assert.Equal(t, tc.expCode, recorder.Code)
			assert.Equal(t, tc.expBody, recorder.Body.String())
			assert.Equal(t, tc.expHeader, recorder.Header())
		})
	}
}
