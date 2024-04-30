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

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestHandlerHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		handler ErrorHandler
		err     error
		expCode int
		accept  string
		expBody string
	}{
		{
			uc:      "authentication error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrAuthentication),
			expCode: http.StatusUnauthorized,
		},
		{
			uc:      "authentication error overridden",
			handler: New(WithAuthenticationErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrAuthentication),
			expCode: http.StatusContinue,
		},
		{
			uc:      "authentication error verbose without mime type set",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrAuthentication),
			expCode: http.StatusUnauthorized,
			expBody: "<p>authentication error</p>",
		},
		{
			uc:      "authorization error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrAuthorization),
			expCode: http.StatusForbidden,
		},
		{
			uc:      "authorization error overridden",
			handler: New(WithAuthorizationErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrAuthorization),
			expCode: http.StatusContinue,
		},
		{
			uc:      "authorization error verbose expecting text/plain",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrAuthorization),
			expCode: http.StatusForbidden,
			accept:  "text/plain",
			expBody: "authorization error",
		},
		{
			uc:      "communication timeout error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrCommunicationTimeout),
			expCode: http.StatusBadGateway,
		},
		{
			uc:      "communication timeout error overridden",
			handler: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrCommunicationTimeout),
			expCode: http.StatusContinue,
		},
		{
			uc:      "communication timeout error verbose expecting application/xml",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrCommunicationTimeout),
			expCode: http.StatusBadGateway,
			accept:  "application/xml",
			expBody: "<error><code>communicationTimeoutError</code></error>",
		},
		{
			uc:      "communication error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrCommunication),
			expCode: http.StatusBadGateway,
		},
		{
			uc:      "communication error overridden",
			handler: New(WithCommunicationErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrCommunication),
			expCode: http.StatusContinue,
		},
		{
			uc:      "communication error verbose expecting application/json",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrCommunication),
			expCode: http.StatusBadGateway,
			accept:  "application/json",
			expBody: "{\"code\":\"communicationError\"}",
		},
		{
			uc:      "precondition error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrArgument),
			expCode: http.StatusBadRequest,
		},
		{
			uc:      "precondition error overridden",
			handler: New(WithPreconditionErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrArgument),
			expCode: http.StatusContinue,
		},
		{
			uc:      "precondition error verbose expecting text/html",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrArgument),
			expCode: http.StatusBadRequest,
			expBody: "<p>argument error</p>",
		},
		{
			uc:      "no rule error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrNoRuleFound),
			expCode: http.StatusNotFound,
		},
		{
			uc:      "no rule error overridden",
			handler: New(WithNoRuleErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrNoRuleFound),
			expCode: http.StatusContinue,
		},
		{
			uc:      "no rule error verbose without mime type",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrNoRuleFound),
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
			uc:      "redirect error verbose without mime type",
			handler: New(WithVerboseErrors(true)),
			err:     &heimdall.RedirectError{RedirectTo: "http://foo.local", Code: http.StatusFound},
			expCode: http.StatusFound,
		},
		{
			uc:      "internal error default",
			handler: New(),
			err:     errorchain.New(heimdall.ErrInternal),
			expCode: http.StatusInternalServerError,
		},
		{
			uc:      "internal error overridden",
			handler: New(WithInternalServerErrorCode(http.StatusContinue)),
			err:     errorchain.New(heimdall.ErrInternal),
			expCode: http.StatusContinue,
		},
		{
			uc:      "internal error verbose without mime type",
			handler: New(WithVerboseErrors(true)),
			err:     errorchain.New(heimdall.ErrInternal),
			expCode: http.StatusInternalServerError,
			expBody: "<p>internal error</p>",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			recorder := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if len(tc.accept) != 0 {
				req.Header.Set("Accept", tc.accept)
			}

			tc.handler.HandleError(recorder, req, tc.err)

			assert.Equal(t, tc.expCode, recorder.Code)
			assert.Equal(t, tc.expBody, recorder.Body.String())
		})
	}
}
