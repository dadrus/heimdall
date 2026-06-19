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
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

type oauth2ChallengeError struct {
	message   string
	tokenType TokenType
}

func (e *oauth2ChallengeError) Error() string {
	if len(e.message) == 0 {
		return "oauth2 assertion error"
	}

	return "oauth2 assertion error: " + e.message
}

func (e *oauth2ChallengeError) commonParams(
	policy ChallengePolicy,
	errorCode string,
) []httpx.Option {
	opts := []httpx.Option{
		httpx.WithPrefix(string(e.tokenType)),
		httpx.WithKeyValue("realm", policy.Realm),
		httpx.WithKeyValue("error", errorCode),
	}

	if len(policy.ErrorURI) != 0 {
		opts = append(opts, httpx.WithKeyValue("error_uri", policy.ErrorURI))
	}

	if policy.IncludeErrorDetails && len(e.message) != 0 {
		opts = append(opts, httpx.WithKeyValue("error_description", e.message))
	}

	return opts
}

type ScopeMismatchError struct {
	required []string
	missing  []string
}

func NewScopeMismatchError(required, missing []string) *ScopeMismatchError {
	return &ScopeMismatchError{
		required: required,
		missing:  missing,
	}
}

func (e *ScopeMismatchError) Error() string            { return "scope matching error" }
func (e *ScopeMismatchError) RequiredScopes() []string { return e.required }
func (e *ScopeMismatchError) MissingScopes() []string  { return e.missing }

type InvalidRequestError struct {
	oauth2ChallengeError
}

func NewInvalidRequestError(tokenType TokenType, message string) *InvalidRequestError {
	return &InvalidRequestError{
		oauth2ChallengeError: oauth2ChallengeError{
			message:   message,
			tokenType: tokenType,
		},
	}
}

func (e *InvalidRequestError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_request")

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusBadRequest,
		Headers:    header,
	}, nil
}

type InvalidTokenError struct {
	oauth2ChallengeError
}

func NewInvalidTokenError(tokenType TokenType, message string) *InvalidTokenError {
	return &InvalidTokenError{
		oauth2ChallengeError: oauth2ChallengeError{
			message:   message,
			tokenType: tokenType,
		},
	}
}

func (e *InvalidTokenError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_token")

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}

type InsufficientScopeError struct {
	oauth2ChallengeError

	requiredScopes []string
}

func NewInsufficientScopeError(
	tokenType TokenType,
	message string,
	requiredScopes []string,
) *InsufficientScopeError {
	return &InsufficientScopeError{
		oauth2ChallengeError: oauth2ChallengeError{
			message:   message,
			tokenType: tokenType,
		},
		requiredScopes: requiredScopes,
	}
}

func (e *InsufficientScopeError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "insufficient_scope")

	if policy.IncludeRequiredScopes && len(e.requiredScopes) != 0 {
		opts = append(opts, httpx.WithKeyValue(
			"scope",
			strings.Join(e.requiredScopes, " "),
		))
	}

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusForbidden,
		Headers:    header,
	}, nil
}

type InvalidDPoPProofError struct {
	oauth2ChallengeError

	algorithms []jose.SignatureAlgorithm
}

func NewInvalidDPoPProofError(message string, algorithms ...jose.SignatureAlgorithm) *InvalidDPoPProofError {
	return &InvalidDPoPProofError{
		oauth2ChallengeError: oauth2ChallengeError{
			message:   message,
			tokenType: TypeDPoP,
		},
		algorithms: algorithms,
	}
}

func (e *InvalidDPoPProofError) Challenge(policy ChallengePolicy) (*Challenge, error) {
	opts := e.commonParams(policy, "invalid_dpop_proof")

	if policy.IncludeDPoPAlgorithms && len(e.algorithms) != 0 {
		// join the allowed algorithms
		builder := &strings.Builder{}
		for i, alg := range e.algorithms {
			builder.WriteString(string(alg))

			if i < len(e.algorithms)-1 {
				builder.WriteString(" ")
			}
		}

		opts = append(opts, httpx.WithKeyValue("algs", builder.String()))
	}

	header := make(http.Header)
	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}

type NonceIssuer interface {
	IssueNonce(binding [32]byte) (string, error)
}

type UseDPoPNonceError struct {
	oauth2ChallengeError

	issuer  NonceIssuer
	binding [32]byte
}

func NewUseDPoPNonceError(
	issuer NonceIssuer,
	binding [32]byte,
	message string,
) *UseDPoPNonceError {
	return &UseDPoPNonceError{
		oauth2ChallengeError: oauth2ChallengeError{
			message:   message,
			tokenType: TypeDPoP,
		},
		issuer:  issuer,
		binding: binding,
	}
}

func (e *UseDPoPNonceError) Challenge(
	policy ChallengePolicy,
) (*Challenge, error) {
	nonce, err := e.issuer.IssueNonce(e.binding)
	if err != nil {
		return nil, err
	}

	opts := e.commonParams(policy, "use_dpop_nonce")
	header := make(http.Header)

	header.Add("WWW-Authenticate", httpx.NewHeader(opts...))
	header.Set("DPoP-Nonce", nonce)

	return &Challenge{
		StatusCode: http.StatusUnauthorized,
		Headers:    header,
	}, nil
}
