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

package oauth2

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestTokenUsageErrorDecoratorMerge(t *testing.T) {
	t.Parallel()

	enabled := true
	disabled := false

	for uc, tc := range map[string]struct {
		decorator TokenUsageErrorDecorator
		other     TokenUsageErrorDecorator
		expected  TokenUsageErrorDecorator
	}{
		"keeps explicitly configured values": {
			decorator: TokenUsageErrorDecorator{
				Enabled:               &disabled,
				IncludeErrorDetails:   &disabled,
				IncludeRequiredScope:  &disabled,
				IncludeDPoPAlgorithms: &disabled,
				ErrorURI:              "https://decorator.example/error",
				Realm:                 "decorator",
			},
			other: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &enabled,
				ErrorURI:              "https://other.example/error",
				Realm:                 "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:               &disabled,
				IncludeErrorDetails:   &disabled,
				IncludeRequiredScope:  &disabled,
				IncludeDPoPAlgorithms: &disabled,
				ErrorURI:              "https://decorator.example/error",
				Realm:                 "decorator",
			},
		},
		"uses other values for zero values": {
			decorator: TokenUsageErrorDecorator{},
			other: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &disabled,
				ErrorURI:              "https://other.example/error",
				Realm:                 "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &disabled,
				ErrorURI:              "https://other.example/error",
				Realm:                 "other",
			},
		},
		"merges partially configured values": {
			decorator: TokenUsageErrorDecorator{
				Enabled:  &disabled,
				Realm:    "decorator",
				ErrorURI: "https://decorator.example/error",
			},
			other: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &enabled,
				ErrorURI:              "https://other.example/error",
				Realm:                 "other",
			},
			expected: TokenUsageErrorDecorator{
				Enabled:               &disabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &enabled,
				ErrorURI:              "https://decorator.example/error",
				Realm:                 "decorator",
			},
		},
		"keeps nil and empty values if other is empty": {
			decorator: TokenUsageErrorDecorator{},
			other:     TokenUsageErrorDecorator{},
			expected:  TokenUsageErrorDecorator{},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.decorator.Merge(tc.other))
		})
	}
}

func TestTokenUsageErrorDecoratorDecorate(t *testing.T) {
	t.Parallel()

	enabled := true
	disabled := false

	for uc, tc := range map[string]struct {
		decorator   TokenUsageErrorDecorator
		createError func(t *testing.T, nhm *NonceHandlerMock) error
		assert      func(t *testing.T, response pipeline.ErrorResponse)
	}{
		"does nothing if not enabled": {
			decorator: TokenUsageErrorDecorator{
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &enabled,
				Realm:                 "example",
				ErrorURI:              "https://example.com/error",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidTokenError(TypeBearer, "assertion error"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Zero(t, response.Code)
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 1)
			},
		},
		"does nothing if explicitly disabled": {
			decorator: TokenUsageErrorDecorator{
				Enabled:               &disabled,
				IncludeErrorDetails:   &enabled,
				IncludeRequiredScope:  &enabled,
				IncludeDPoPAlgorithms: &enabled,
				Realm:                 "example",
				ErrorURI:              "https://example.com/error",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidTokenError(TypeBearer, "assertion error"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Zero(t, response.Code)
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 1)
			},
		},
		"does nothing if cause is not challenge capable": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
				Realm:   "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(pipeline.ErrArgument)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Zero(t, response.Code)
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 1)
			},
		},
		"sets internal server error if challenge creation fails": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
				Realm:   "example",
			},
			createError: func(t *testing.T, nhm *NonceHandlerMock) error {
				t.Helper()

				nhm.EXPECT().IssueNonce(mock.Anything).Return("", assert.AnError)

				return errorchain.New(pipeline.ErrAuthentication).
					CausedBy(NewUseDPoPNonceError(nhm, [32]byte{}, "some error"))
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, response.Code)
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 1)
			},
		},
		"malformed bearer request without optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
				Realm:   "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidRequestError(TypeBearer, ""),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="example", error="invalid_request"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"malformed bearer request with all common optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled:             &enabled,
				IncludeErrorDetails: &enabled,
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidRequestError(TypeBearer, "malformed request: invalid JWT format"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="example", error="invalid_request", error_uri="https://example.com/error", error_description="malformed request: invalid JWT format"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid bearer token without optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
				Realm:   "Please authenticate",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidTokenError(TypeBearer, ""),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="Please authenticate", error="invalid_token"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid bearer token with all common optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled:             &enabled,
				IncludeErrorDetails: &enabled,
				ErrorURI:            "https://example.com/error",
				Realm:               "Please authenticate",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidTokenError(TypeBearer, "assertion error"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="Please authenticate", error="invalid_token", error_uri="https://example.com/error", error_description="assertion error"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"insufficient bearer scope without optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInsufficientScopeError(TypeBearer, "", nil),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusForbidden, response.Code)
				assert.Equal(t, []string{
					`Bearer error="insufficient_scope"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"insufficient bearer scope with required scope only": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              &enabled,
				IncludeRequiredScope: &enabled,
				Realm:                "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInsufficientScopeError(TypeBearer, "scope matching error", []string{"foo", "bar"}),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusForbidden, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="example", error="insufficient_scope", scope="foo bar"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"insufficient bearer scope with all optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled:              &enabled,
				IncludeErrorDetails:  &enabled,
				IncludeRequiredScope: &enabled,
				Realm:                "example",
				ErrorURI:             "https://example.com/error",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInsufficientScopeError(TypeBearer, "scope matching error", []string{"foo", "bar"}),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusForbidden, response.Code)
				assert.Equal(t, []string{
					`Bearer realm="example", error="insufficient_scope", error_uri="https://example.com/error", error_description="scope matching error", scope="foo bar"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid dpop token uses dpop scheme": {
			decorator: TokenUsageErrorDecorator{
				Enabled:             &enabled,
				IncludeErrorDetails: &enabled,
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidTokenError(TypeDPoP, "malformed token type - DPoP expected"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="invalid_token", error_uri="https://example.com/error", error_description="malformed token type - DPoP expected"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid dpop proof without algorithms if disabled by policy": {
			decorator: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeDPoPAlgorithms: &disabled,
				ErrorURI:              "https://example.com/error",
				Realm:                 "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidDPoPProofError("proof is missing", jose.ES256, jose.EdDSA),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="invalid_dpop_proof", error_uri="https://example.com/error", error_description="proof is missing"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid dpop proof without algorithms if not configured by policy": {
			decorator: TokenUsageErrorDecorator{
				Enabled:             &enabled,
				IncludeErrorDetails: &enabled,
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidDPoPProofError("proof is missing", jose.ES256, jose.EdDSA),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="invalid_dpop_proof", error_uri="https://example.com/error", error_description="proof is missing"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid dpop proof with algorithms": {
			decorator: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeDPoPAlgorithms: &enabled,
				ErrorURI:              "https://example.com/error",
				Realm:                 "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidDPoPProofError("proof is missing", jose.ES256, jose.EdDSA),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="invalid_dpop_proof", error_uri="https://example.com/error", error_description="proof is missing", algs="ES256 EdDSA"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"invalid dpop proof without algorithms if error has none": {
			decorator: TokenUsageErrorDecorator{
				Enabled:               &enabled,
				IncludeErrorDetails:   &enabled,
				IncludeDPoPAlgorithms: &enabled,
				ErrorURI:              "https://example.com/error",
				Realm:                 "example",
			},
			createError: func(t *testing.T, _ *NonceHandlerMock) error {
				t.Helper()

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewInvalidDPoPProofError("proof is missing"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="invalid_dpop_proof", error_uri="https://example.com/error", error_description="proof is missing"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 2)
			},
		},
		"use dpop nonce challenge without optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled: &enabled,
				Realm:   "example",
			},
			createError: func(t *testing.T, nhm *NonceHandlerMock) error {
				t.Helper()

				var binding [32]byte
				nhm.EXPECT().IssueNonce(binding).Return("nonce-value", nil)

				return errorchain.New(pipeline.ErrAuthentication).
					CausedBy(NewUseDPoPNonceError(nhm, binding, ""))
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="use_dpop_nonce"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"nonce-value"}, response.Headers[http.CanonicalHeaderKey("DPoP-Nonce")])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 3)
			},
		},
		"use dpop nonce challenge with all common optional parameters": {
			decorator: TokenUsageErrorDecorator{
				Enabled:             &enabled,
				IncludeErrorDetails: &enabled,
				ErrorURI:            "https://example.com/error",
				Realm:               "example",
			},
			createError: func(t *testing.T, nhm *NonceHandlerMock) error {
				t.Helper()

				var binding [32]byte
				nhm.EXPECT().IssueNonce(binding).Return("nonce-value", nil)

				return errorchain.New(pipeline.ErrAuthentication).CausedBy(
					NewUseDPoPNonceError(nhm, binding, "nonce is invalid"),
				)
			},
			assert: func(t *testing.T, response pipeline.ErrorResponse) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, response.Code)
				assert.Equal(t, []string{
					`DPoP realm="example", error="use_dpop_nonce", error_uri="https://example.com/error", error_description="nonce is invalid"`,
				}, response.Headers[wwwAuthenticateHeader])
				assert.Equal(t, []string{"nonce-value"}, response.Headers[http.CanonicalHeaderKey("DPoP-Nonce")])
				assert.Equal(t, []string{"preserved"}, response.Headers["X-Test"])
				require.Len(t, response.Headers, 3)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			nhm := NewNonceHandlerMock(t)

			response := pipeline.ErrorResponse{
				Headers: map[string][]string{"X-Test": {"preserved"}},
			}

			tc.decorator.Decorate(tc.createError(t, nhm), &response)

			tc.assert(t, response)
		})
	}
}
