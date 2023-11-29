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

package admission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"

	"github.com/dadrus/heimdall/internal/x"
)

func TestNewWebhookServeHTTP(t *testing.T) {
	t.Parallel()

	testRequestPayload := `
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "ce409862-eae0-4704-b7d5-46634efdaf9b",
    "kind": {
      "group": "test.test",
      "version": "v1",
      "kind": "Resource"
    },
    "resource": {
      "group": "test.test",
      "version": "v1",
      "resource": "resources"
    },
    "requestKind": {
      "group": "test.test",
      "version": "v1",
      "kind": "Resource"
    },
    "requestResource": {
      "group": "test.test",
      "version": "v1",
      "resource": "test.test"
    },
    "name": "some-object",
    "namespace": "test",
    "operation": "CREATE",
    "userInfo": {
      "username": "kubernetes-admin",
      "groups": [
        "system:masters",
        "system:authenticated"
      ]
    },
    "object": {
      "apiVersion": "test.test/v1",
      "kind": "Resource",
      "metadata": {
        "creationTimestamp": "2023-10-25T17:13:37Z",
        "generation": 1,
        "labels": { "app.kubernetes.io/name": "test-app" },
        "name": "test-app-resources",
        "namespace": "test",
        "uid": "28703aca-bb5a-4355-8542-4b37b1146553"
      },
      "spec": {
        "something": "something",
      }
    },
    "oldObject": null,
    "dryRun": false,
    "options": {
      "kind": "CreateOptions",
      "apiVersion": "meta.k8s.io/v1",
      "fieldManager": "kubectl-client-side-apply",
      "fieldValidation": "Strict"
    }
  }
}
`

	for _, tc := range []struct {
		uc           string
		request      func(t *testing.T, URL string) *http.Request
		setupHandler func(t *testing.T, handler *HandlerMock)
		assert       func(t *testing.T, resp *http.Response)
	}{
		{
			uc: "invalid content type",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, nil)
				require.NoError(t, err)

				return req
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.False(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusBadRequest, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "unexpected contentType")
				assert.Empty(t, status.Reason)
				require.Nil(t, status.Details)
			},
		},
		{
			uc: "failed decoding request",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, strings.NewReader("foo"))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.False(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusBadRequest, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "failed decoding request")
				assert.Contains(t, status.Reason, "invalid character")
				require.NotNil(t, status.Details)
				require.Len(t, status.Details.Causes, 1)
				assert.Contains(t, status.Details.Causes[0].Message, "invalid character")
			},
		},
		{
			uc: "valid request without timeout",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, strings.NewReader(testRequestPayload))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupHandler: func(t *testing.T, handler *HandlerMock) {
				t.Helper()

				handler.EXPECT().Handle(
					mock.MatchedBy(func(ctx context.Context) bool {
						_, ok := ctx.Deadline()

						return !ok
					}),
					mock.Anything).
					Return(NewResponse(http.StatusOK, "All fine"))
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Equal(t, "All fine", status.Message)
			},
		},
		{
			uc: "valid request with valid timeout",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				query := url.Values{
					"timeout": []string{"5s"},
				}
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL+"?"+query.Encode(),
					strings.NewReader(testRequestPayload))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupHandler: func(t *testing.T, handler *HandlerMock) {
				t.Helper()

				handler.EXPECT().Handle(
					mock.MatchedBy(func(ctx context.Context) bool {
						_, ok := ctx.Deadline()

						return ok
					}),
					mock.Anything).
					Return(NewResponse(http.StatusOK, "All fine"))
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Equal(t, "All fine", status.Message)
			},
		},
		{
			uc: "valid request with invalid timeout",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				query := url.Values{
					"timeout": []string{"5g"},
				}
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL+"?"+query.Encode(),
					strings.NewReader(testRequestPayload))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupHandler: func(t *testing.T, handler *HandlerMock) {
				t.Helper()

				handler.EXPECT().Handle(
					mock.MatchedBy(func(ctx context.Context) bool {
						_, ok := ctx.Deadline()

						return !ok
					}),
					mock.Anything).
					Return(NewResponse(http.StatusOK, "All fine"))
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Equal(t, "All fine", status.Message)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			setupMock := x.IfThenElse(
				tc.setupHandler != nil,
				tc.setupHandler,
				func(t *testing.T, _ *HandlerMock) { t.Helper() },
			)

			handler := NewHandlerMock(t)
			setupMock(t, handler)

			srv := httptest.NewServer(NewWebhook(handler))
			defer srv.Close()

			client := &http.Client{Transport: &http.Transport{}}

			// WHEN
			resp, err := client.Do(tc.request(t, srv.URL))

			// THEN
			require.NoError(t, err)

			defer resp.Body.Close()

			tc.assert(t, resp)
			handler.AssertExpectations(t)
		})
	}
}
