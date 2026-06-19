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
	"github.com/stretchr/testify/require"
)

func TestOAuth2ChallengeErrorError(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err      oauth2ChallengeError
		expected string
	}{
		"without message": {
			err:      oauth2ChallengeError{},
			expected: "oauth2 assertion error",
		},
		"with message": {
			err: oauth2ChallengeError{
				message: "something went wrong",
			},
			expected: "oauth2 assertion error: something went wrong",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

func TestScopeMismatchError(t *testing.T) {
	t.Parallel()

	required := []string{"read", "write"}
	missing := []string{"write"}

	err := NewScopeMismatchError(required, missing)

	assert.Equal(t, "scope matching error", err.Error())
	assert.Equal(t, required, err.RequiredScopes())
	assert.Equal(t, missing, err.MissingScopes())
}

func TestInvalidRequestErrorChallenge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err    *InvalidRequestError
		policy ChallengePolicy
		assert func(t *testing.T, err error, challenge *Challenge)
	}{
		"bearer challenge with all optional parameters": {
			err: NewInvalidRequestError(TypeBearer, "invalid request"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusBadRequest, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_request"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="invalid request"`)
			},
		},
		"dpop challenge with all optional parameters": {
			err: NewInvalidRequestError(TypeDPoP, "invalid request"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusBadRequest, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_request"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="invalid request"`)
			},
		},
		"without error uri": {
			err: NewInvalidRequestError(TypeBearer, "invalid request"),
			policy: ChallengePolicy{
				Realm:               "example",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusBadRequest, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_request"`)
				assert.Contains(t, header, `error_description="invalid request"`)
				assert.NotContains(t, header, "error_uri")
			},
		},
		"without error description if disabled by policy": {
			err: NewInvalidRequestError(TypeBearer, "invalid request"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: false,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusBadRequest, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_request"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without error description if message is empty": {
			err: NewInvalidRequestError(TypeBearer, ""),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusBadRequest, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_request"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			challenge, err := tc.err.Challenge(tc.policy)

			tc.assert(t, err, challenge)
		})
	}
}

func TestInvalidTokenErrorChallenge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err    *InvalidTokenError
		policy ChallengePolicy
		assert func(t *testing.T, err error, challenge *Challenge)
	}{
		"bearer challenge with all optional parameters": {
			err: NewInvalidTokenError(TypeBearer, "token expired"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="token expired"`)
			},
		},
		"dpop challenge with all optional parameters": {
			err: NewInvalidTokenError(TypeDPoP, "token expired"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="token expired"`)
			},
		},
		"without error uri": {
			err: NewInvalidTokenError(TypeBearer, "token expired"),
			policy: ChallengePolicy{
				Realm:               "example",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, `error_description="token expired"`)
				assert.NotContains(t, header, "error_uri")
			},
		},
		"without error description if disabled by policy": {
			err: NewInvalidTokenError(TypeBearer, "token expired"),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: false,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without error description if message is empty": {
			err: NewInvalidTokenError(TypeBearer, ""),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_token"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			challenge, err := tc.err.Challenge(tc.policy)

			tc.assert(t, err, challenge)
		})
	}
}

func TestInsufficientScopeErrorChallenge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err    *InsufficientScopeError
		policy ChallengePolicy
		assert func(t *testing.T, err error, challenge *Challenge)
	}{
		"bearer challenge with all optional parameters": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"required scopes are missing",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="required scopes are missing"`)
				assert.Contains(t, header, `scope="read write"`)
			},
		},
		"dpop challenge with all optional parameters": {
			err: NewInsufficientScopeError(
				TypeDPoP,
				"required scopes are missing",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="required scopes are missing"`)
				assert.Contains(t, header, `scope="read write"`)
			},
		},
		"without error uri": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"required scopes are missing",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_description="required scopes are missing"`)
				assert.Contains(t, header, `scope="read write"`)
				assert.NotContains(t, header, "error_uri")
			},
		},
		"without error description if disabled by policy": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"required scopes are missing",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   false,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `scope="read write"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without error description if message is empty": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `scope="read write"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without required scopes if disabled by policy": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"required scopes are missing",
				[]string{"read", "write"},
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: false,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="required scopes are missing"`)
				assert.NotContains(t, header, "scope=")
			},
		},
		"without required scopes if none are present": {
			err: NewInsufficientScopeError(
				TypeBearer,
				"required scopes are missing",
				nil,
			),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeRequiredScopes: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusForbidden, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "Bearer")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="insufficient_scope"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="required scopes are missing"`)
				assert.NotContains(t, header, "scope=")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			challenge, err := tc.err.Challenge(tc.policy)

			tc.assert(t, err, challenge)
		})
	}
}

func TestInvalidDPoPProofErrorChallenge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err    *InvalidDPoPProofError
		policy ChallengePolicy
		assert func(t *testing.T, err error, challenge *Challenge)
	}{
		"challenge with all optional parameters": {
			err: NewInvalidDPoPProofError("proof is invalid", jose.ES256, jose.EdDSA),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeDPoPAlgorithms: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="proof is invalid"`)
				assert.Contains(t, header, `algs="ES256 EdDSA"`)
			},
		},
		"without error uri": {
			err: NewInvalidDPoPProofError("proof is invalid", jose.ES256, jose.EdDSA),
			policy: ChallengePolicy{
				Realm:                 "example",
				IncludeErrorDetails:   true,
				IncludeDPoPAlgorithms: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_description="proof is invalid"`)
				assert.Contains(t, header, `algs="ES256 EdDSA"`)
				assert.NotContains(t, header, "error_uri")
			},
		},
		"without error description if disabled by policy": {
			err: NewInvalidDPoPProofError("proof is invalid", jose.ES256, jose.EdDSA),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   false,
				IncludeDPoPAlgorithms: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `algs="ES256 EdDSA"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without error description if message is empty": {
			err: NewInvalidDPoPProofError("", jose.ES256, jose.EdDSA),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeDPoPAlgorithms: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `algs="ES256 EdDSA"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without algorithms if not included by policy": {
			err: NewInvalidDPoPProofError("proof is invalid", jose.ES256, jose.EdDSA),
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="proof is invalid"`)
				assert.NotContains(t, header, "algs=")
			},
		},
		"without algorithms if not provided": {
			err: NewInvalidDPoPProofError("proof is invalid"),
			policy: ChallengePolicy{
				Realm:                 "example",
				ErrorURI:              "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails:   true,
				IncludeDPoPAlgorithms: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="invalid_dpop_proof"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="proof is invalid"`)
				assert.NotContains(t, header, "algs=")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			challenge, err := tc.err.Challenge(tc.policy)

			tc.assert(t, err, challenge)
		})
	}
}

func TestUseDPoPNonceErrorChallenge(t *testing.T) {
	t.Parallel()

	var binding [32]byte
	copy(binding[:], "0123456789abcdef0123456789abcdef")

	for uc, tc := range map[string]struct {
		setup  func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError
		policy ChallengePolicy
		assert func(t *testing.T, err error, challenge *Challenge)
	}{
		"challenge with all optional parameters": {
			setup: func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError {
				t.Helper()

				issuer.EXPECT().
					IssueNonce(binding).
					Return("nonce-value", nil)

				return NewUseDPoPNonceError(issuer, binding, "nonce is invalid")
			},
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)
				assert.Equal(t, "nonce-value", challenge.Headers.Get("DPoP-Nonce"))

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="use_dpop_nonce"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.Contains(t, header, `error_description="nonce is invalid"`)
			},
		},
		"without error uri": {
			setup: func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError {
				t.Helper()

				issuer.EXPECT().
					IssueNonce(binding).
					Return("nonce-value", nil)

				return NewUseDPoPNonceError(issuer, binding, "nonce is invalid")
			},
			policy: ChallengePolicy{
				Realm:               "example",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)
				assert.Equal(t, "nonce-value", challenge.Headers.Get("DPoP-Nonce"))

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="use_dpop_nonce"`)
				assert.Contains(t, header, `error_description="nonce is invalid"`)
				assert.NotContains(t, header, "error_uri")
			},
		},
		"without error description if disabled by policy": {
			setup: func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError {
				t.Helper()

				issuer.EXPECT().
					IssueNonce(binding).
					Return("nonce-value", nil)

				return NewUseDPoPNonceError(issuer, binding, "nonce is invalid")
			},
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: false,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)
				assert.Equal(t, "nonce-value", challenge.Headers.Get("DPoP-Nonce"))

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="use_dpop_nonce"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"without error description if message is empty": {
			setup: func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError {
				t.Helper()

				issuer.EXPECT().
					IssueNonce(binding).
					Return("nonce-value", nil)

				return NewUseDPoPNonceError(issuer, binding, "")
			},
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, challenge)

				assert.Equal(t, http.StatusUnauthorized, challenge.StatusCode)
				assert.Equal(t, "nonce-value", challenge.Headers.Get("DPoP-Nonce"))

				header := challenge.Headers.Get("WWW-Authenticate")
				require.NotEmpty(t, header)

				assert.Contains(t, header, "DPoP")
				assert.Contains(t, header, `realm="example"`)
				assert.Contains(t, header, `error="use_dpop_nonce"`)
				assert.Contains(t, header, `error_uri="https://docs.example.org/oauth2/errors"`)
				assert.NotContains(t, header, "error_description")
			},
		},
		"returns nonce issuer error": {
			setup: func(t *testing.T, issuer *NonceHandlerMock) *UseDPoPNonceError {
				t.Helper()

				issuer.EXPECT().
					IssueNonce(binding).
					Return("", assert.AnError)

				return NewUseDPoPNonceError(issuer, binding, "nonce is invalid")
			},
			policy: ChallengePolicy{
				Realm:               "example",
				ErrorURI:            "https://docs.example.org/oauth2/errors",
				IncludeErrorDetails: true,
			},
			assert: func(t *testing.T, err error, challenge *Challenge) {
				t.Helper()

				require.ErrorIs(t, err, assert.AnError)
				assert.Nil(t, challenge)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			issuer := NewNonceHandlerMock(t)
			dpopErr := tc.setup(t, issuer)

			challenge, err := dpopErr.Challenge(tc.policy)

			tc.assert(t, err, challenge)
		})
	}
}
