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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/nonce"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type nonceHandler interface {
	ResolveKey(kid string) (nonce.Key, error)
	IssueNonce(binding [32]byte) (string, error)
}

type DPoPClaims struct {
	HTTPMethod      string    `json:"htm"`
	HTTPURI         string    `json:"htu"`
	AccessTokenHash string    `json:"ath"`
	IssuedAt        time.Time `json:"iat"`
	JTI             string    `json:"jti"`
	Nonce           string    `json:"nonce,omitempty"`
}

//nolint:cyclop, funlen
func (c DPoPClaims) Validate(
	ctx pipeline.Context,
	nonceHandler nonceHandler,
	maxAge, leeway time.Duration,
	replayAllowed, nonceRequired bool,
	rawToken string,
) error {
	httpURI := ctx.Request().URL.URL
	httpURI.RawQuery = ""
	httpURI.Fragment = ""

	expectedHash := sha256.Sum256(stringx.ToBytes(rawToken))
	now := time.Now()
	cch := cache.Ctx(ctx.Context())

	var jtiKey string

	if len(c.JTI) == 0 {
		return NewInvalidDPoPProofError("jti is missing")
	}

	if !replayAllowed {
		jtiHash := sha256.Sum256(stringx.ToBytes(c.JTI))
		jtiKey = "dpop:jti:" + base64.RawURLEncoding.EncodeToString(jtiHash[:])

		if _, err := cch.Get(ctx.Context(), jtiKey); err == nil {
			return NewInvalidDPoPProofError("replay detected")
		}
	}

	if c.IssuedAt.IsZero() {
		return NewInvalidDPoPProofError("iat is missing")
	}

	if now.Add(leeway).Before(c.IssuedAt) {
		return NewInvalidDPoPProofError("iat is in the future")
	}

	ttl := time.Until(c.IssuedAt.Add(maxAge).Add(leeway))
	if ttl <= 0 {
		return NewInvalidDPoPProofError("proof is too old")
	}

	if c.HTTPMethod != ctx.Request().Method {
		return NewInvalidDPoPProofError("htm does not match request method")
	}

	if c.HTTPURI != httpURI.String() {
		return NewInvalidDPoPProofError("htu does not match request URI")
	}

	gotHash, err := base64.RawURLEncoding.DecodeString(c.AccessTokenHash)
	if err != nil {
		return NewInvalidDPoPProofError("ath is malformed")
	}

	if subtle.ConstantTimeCompare(expectedHash[:], gotHash) != 1 {
		return NewInvalidDPoPProofError("ath does not match expected token hash value")
	}

	if nonceRequired {
		if len(c.Nonce) == 0 {
			return NewUseDPoPNonceError(nonceHandler, expectedHash, "nonce is missing")
		}

		if err := nonce.ValidateNonce(
			c.Nonce,
			nonceHandler,
			nonce.WithMaxAge(maxAge),
			nonce.WithBinding(expectedHash),
		); err != nil {
			return errorchain.New(NewUseDPoPNonceError(nonceHandler, expectedHash, "nonce is invalid")).
				CausedBy(err)
		}
	}

	if !replayAllowed {
		if err := cch.Set(ctx.Context(), jtiKey, []byte{1}, ttl); err != nil {
			return errorchain.NewWithMessage(
				pipeline.ErrInternal,
				"failed to remember DPoP proof jti",
			).CausedBy(err)
		}
	}

	return nil
}
