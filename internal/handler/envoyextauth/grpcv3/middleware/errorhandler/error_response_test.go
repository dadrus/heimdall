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
	"testing"

	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestErrorResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc           string
		code         int
		err          error
		offeredType  string
		expectedType string
		expBody      string
	}{
		{
			uc:           "select text/plain from multiple offered",
			code:         http.StatusForbidden,
			err:          errorchain.NewWithMessage(heimdall.ErrAuthorization, "test"),
			offeredType:  "application/json;q=0.3,text/html;q=0.5,text/plain",
			expectedType: "text/plain",
			expBody:      "authorization error: test",
		},
		{
			uc:           "select text/html doe to unknown offered type",
			code:         http.StatusForbidden,
			err:          errorchain.NewWithMessage(heimdall.ErrAuthorization, "test"),
			offeredType:  "foo/bar;q=0.5,bar/foo;q=0.6",
			expectedType: "text/html",
			expBody:      "<p>authorization error: test</p>",
		},
		{
			uc:           "select text/html from multiple offered",
			code:         http.StatusForbidden,
			err:          errorchain.NewWithMessage(heimdall.ErrAuthorization, "test"),
			offeredType:  "application/json;q=0.3,text/html;q=0.5,text/html;q=0.8,*/*;q=0.2",
			expectedType: "text/html",
			expBody:      "<p>authorization error: test</p>",
		},
		{
			uc:           "select appliction/xml from multiple offered",
			code:         http.StatusForbidden,
			err:          errorchain.NewWithMessage(heimdall.ErrAuthorization, "test"),
			offeredType:  "application/json;q=0.3,text/html;q=0.5,text/plain;q=0.2,application/xml;q=0.8",
			expectedType: "application/xml",
			expBody:      "<error><code>authorizationError</code><message>test</message></error>",
		},
		{
			uc:           "select appliction/json from multiple offered",
			code:         http.StatusForbidden,
			err:          errorchain.NewWithMessage(heimdall.ErrAuthorization, "test"),
			offeredType:  "application/xml;q=0.3,text/html;q=0.5,text/plain;q=0.2,application/json;q=0.8",
			expectedType: "application/json",
			expBody:      "{\"code\":\"authorizationError\",\"message\":\"test\"}",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			resp := errorResponse(tc.code, tc.err, true, tc.offeredType)

			// THEN
			require.NotNil(t, resp)

			assert.Equal(t, int32(tc.code), resp.Status.Code)

			deniedResp := resp.GetDeniedResponse()
			assert.Equal(t, envoy_type.StatusCode(tc.code), deniedResp.Status.Code)
			assert.Equal(t, "Content-Type", deniedResp.Headers[0].Header.Key)
			assert.Equal(t, tc.expectedType, deniedResp.Headers[0].Header.Value)
			assert.Equal(t, tc.expBody, deniedResp.Body)
		})
	}
}
