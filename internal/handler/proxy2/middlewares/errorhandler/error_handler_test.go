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

package errorhandler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestHandlerHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		handler *ErrorHandler
		err     error
		expCode int
		expBody string
	}{
		{
			uc:      "authentication error default",
			handler: New(),
			err:     heimdall.ErrAuthentication,
			expCode: http.StatusUnauthorized,
		},
		{
			uc:      "authentication error overridden",
			handler: New(WithAuthenticationErrorCode(http.StatusContinue)),
			err:     heimdall.ErrAuthentication,
			expCode: http.StatusContinue,
		},
		{
			uc:      "authentication error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrAuthentication,
			expCode: http.StatusUnauthorized,
			expBody: "<p>authentication error</p>",
		},
		{
			uc:      "authorization error default",
			handler: New(),
			err:     heimdall.ErrAuthorization,
			expCode: http.StatusForbidden,
		},
		{
			uc:      "authorization error overridden",
			handler: New(WithAuthorizationErrorCode(http.StatusContinue)),
			err:     heimdall.ErrAuthorization,
			expCode: http.StatusContinue,
		},
		{
			uc:      "authorization error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrAuthorization,
			expCode: http.StatusForbidden,
			expBody: "<p>authorization error</p>",
		},
		{
			uc:      "communication timeout error default",
			handler: New(),
			err:     heimdall.ErrCommunicationTimeout,
			expCode: http.StatusBadGateway,
		},
		{
			uc:      "communication timeout error overridden",
			handler: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:     heimdall.ErrCommunicationTimeout,
			expCode: http.StatusContinue,
		},
		{
			uc:      "communication timeout error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrCommunicationTimeout,
			expCode: http.StatusBadGateway,
			expBody: "<p>communication timeout error</p>",
		},
		{
			uc:      "communication error default",
			handler: New(),
			err:     heimdall.ErrCommunication,
			expCode: http.StatusBadGateway,
		},
		{
			uc:      "communication error overridden",
			handler: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:     heimdall.ErrCommunication,
			expCode: http.StatusContinue,
		},
		{
			uc:      "communication error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrCommunication,
			expCode: http.StatusBadGateway,
			expBody: "<p>communication error</p>",
		},
		{
			uc:      "precondition error default",
			handler: New(),
			err:     heimdall.ErrArgument,
			expCode: http.StatusBadRequest,
		},
		{
			uc:      "precondition error overridden",
			handler: New(WithPreconditionErrorCode(http.StatusContinue)),
			err:     heimdall.ErrArgument,
			expCode: http.StatusContinue,
		},
		{
			uc:      "precondition error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrArgument,
			expCode: http.StatusBadRequest,
			expBody: "<p>argument error</p>",
		},
		{
			uc:      "method error default",
			handler: New(),
			err:     heimdall.ErrMethodNotAllowed,
			expCode: http.StatusMethodNotAllowed,
		},
		{
			uc:      "method error overridden",
			handler: New(WithMethodErrorCode(http.StatusContinue)),
			err:     heimdall.ErrMethodNotAllowed,
			expCode: http.StatusContinue,
		},
		{
			uc:      "method error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrMethodNotAllowed,
			expCode: http.StatusMethodNotAllowed,
			expBody: "<p>method not allowed</p>",
		},
		{
			uc:      "no rule error default",
			handler: New(),
			err:     heimdall.ErrNoRuleFound,
			expCode: http.StatusNotFound,
		},
		{
			uc:      "no rule error overridden",
			handler: New(WithNoRuleErrorCode(http.StatusContinue)),
			err:     heimdall.ErrNoRuleFound,
			expCode: http.StatusContinue,
		},
		{
			uc:      "no rule error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrNoRuleFound,
			expCode: http.StatusNotFound,
			expBody: "<p>no rule found</p>",
		},
		{
			uc:      "redirect error",
			handler: New(),
			err:     &heimdall.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expCode: http.StatusFound,
		},
		{
			uc:      "redirect error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     &heimdall.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expCode: http.StatusFound,
		},
		{
			uc:      "internal error default",
			handler: New(),
			err:     heimdall.ErrInternal,
			expCode: http.StatusInternalServerError,
		},
		{
			uc:      "internal error overridden",
			handler: New(WithInternalServerErrorCode(http.StatusContinue)),
			err:     heimdall.ErrInternal,
			expCode: http.StatusContinue,
		},
		{
			uc:      "internal error verbose",
			handler: New(WithVerboseErrors(true)),
			err:     heimdall.ErrInternal,
			expCode: http.StatusInternalServerError,
			expBody: "<p>internal error</p>",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			recorder := httptest.NewRecorder()

			tc.handler.HandleError(recorder, httptest.NewRequest(http.MethodGet, "/foo", nil), tc.err)

			assert.Equal(t, tc.expCode, recorder.Code)
			assert.Equal(t, tc.expBody, recorder.Body.String())
		})
	}
}
