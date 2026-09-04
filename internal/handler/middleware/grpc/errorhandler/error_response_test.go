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
	"google.golang.org/grpc/codes"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestErrorResponse(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		grpcCode    codes.Code
		httpCode    int
		err         error
		verbose     bool
		offeredType string
		expBody     string
		expHeaders  map[string][]string
	}{
		"select text/plain from multiple offered": {
			grpcCode:    codes.NotFound,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "test"),
			verbose:     true,
			offeredType: "application/json;q=0.3,text/html;q=0.5,text/plain",
			expBody:     "authorization error: test",
			expHeaders: map[string][]string{
				"Content-Type": {"text/plain"},
			},
		},
		"select text/html doe to unknown offered type": {
			grpcCode:    codes.Internal,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "test"),
			verbose:     true,
			offeredType: "foo/bar;q=0.5,bar/foo;q=0.6",
			expBody:     "<p>authorization error: test</p>",
			expHeaders: map[string][]string{
				"Content-Type": {"text/html"},
			},
		},
		"select text/html from multiple offered": {
			grpcCode:    codes.PermissionDenied,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "test"),
			verbose:     true,
			offeredType: "application/json;q=0.3,text/html;q=0.5,text/html;q=0.8,*/*;q=0.2",
			expBody:     "<p>authorization error: test</p>",
			expHeaders: map[string][]string{
				"Content-Type": {"text/html"},
			},
		},
		"select appliction/xml from multiple offered": {
			grpcCode:    codes.PermissionDenied,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "test"),
			verbose:     true,
			offeredType: "application/json;q=0.3,text/html;q=0.5,text/plain;q=0.2,application/xml;q=0.8",
			expBody:     "<error><code>authorizationError</code><message>test</message></error>",
			expHeaders: map[string][]string{
				"Content-Type": {"application/xml"},
			},
		},
		"select appliction/json from multiple offered": {
			grpcCode:    codes.PermissionDenied,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "test"),
			verbose:     true,
			offeredType: "application/xml;q=0.3,text/html;q=0.5,text/plain;q=0.2,application/json;q=0.8",
			expBody:     "{\"code\":\"authorizationError\",\"message\":\"test\"}",
			expHeaders: map[string][]string{
				"Content-Type": {"application/json"},
			},
		},
		"escape error in text/html": {
			// ensuring that error is escaped if it somehow should contain data from outside
			// should not be possible (TM)
			grpcCode:    codes.PermissionDenied,
			httpCode:    http.StatusForbidden,
			err:         errorchain.NewWithMessage(pipeline.ErrAuthorization, "<script>alert(1)</script>"),
			verbose:     true,
			offeredType: "text/html",
			expBody:     "<p>authorization error: &lt;script&gt;alert(1)&lt;/script&gt;</p>",
			expHeaders: map[string][]string{
				"Content-Type": {"text/html"},
			},
		},
		"authentication challenge": {
			grpcCode: codes.Unauthenticated,
			httpCode: http.StatusUnauthorized,
			err: pipeline.NewAuthenticationChallengeError(
				pipeline.ErrAuthentication,
				`Basic realm="Please authenticate"`,
			),
			expHeaders: map[string][]string{
				"WWW-Authenticate": {`Basic realm="Please authenticate"`},
			},
		},
		"authentication challenge with verbose response": {
			grpcCode: codes.Unauthenticated,
			httpCode: http.StatusUnauthorized,
			err: pipeline.NewAuthenticationChallengeError(
				pipeline.ErrAuthentication,
				`Basic realm="Please authenticate"`,
			),
			verbose:     true,
			offeredType: "text/html",
			expBody:     "<p>authentication error</p>",
			expHeaders: map[string][]string{
				"Content-Type":     {"text/html"},
				"WWW-Authenticate": {`Basic realm="Please authenticate"`},
			},
		},
		"authentication error without challenge": {
			grpcCode:   codes.Unauthenticated,
			httpCode:   http.StatusUnauthorized,
			err:        errorchain.New(pipeline.ErrAuthentication),
			expHeaders: map[string][]string{},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			resp := errorResponse(tc.grpcCode, tc.httpCode, tc.err, tc.verbose, tc.offeredType)

			// THEN
			require.NotNil(t, resp)

			assert.Equal(t, int32(tc.grpcCode), resp.GetStatus().GetCode()) //nolint:gosec

			deniedResp := resp.GetDeniedResponse()

			assert.Equal(t, envoy_type.StatusCode(tc.httpCode), deniedResp.GetStatus().GetCode()) //nolint:gosec
			assert.Equal(t, tc.expBody, deniedResp.GetBody())

			headers := make(map[string][]string)
			for _, option := range deniedResp.GetHeaders() {
				header := option.GetHeader()
				if header != nil {
					headers[header.GetKey()] = append(headers[header.GetKey()], header.GetValue())
				}
			}

			assert.Equal(t, tc.expHeaders, headers)
		})
	}
}
