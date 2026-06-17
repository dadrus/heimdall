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

package oauth2

import (
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

const defaultLeeway = 10 * time.Second

type Expectation struct {
	TrustedIssuers    []string                  `mapstructure:"issuers"`
	ScopesMatcher     ScopesMatcher             `mapstructure:"scopes"`
	Audiences         []string                  `mapstructure:"audience"`
	AllowedAlgorithms []jose.SignatureAlgorithm `mapstructure:"allowed_algorithms"`
	ValidityLeeway    time.Duration             `mapstructure:"validity_leeway"`
	ProofOfPossession PoPStrategy               `mapstructure:"proof_of_possession"`
}

func (e Expectation) Merge(other Expectation) Expectation {
	e.TrustedIssuers = x.IfThenElse(len(e.TrustedIssuers) != 0, e.TrustedIssuers, other.TrustedIssuers)
	e.ScopesMatcher = x.IfThenElse(e.ScopesMatcher != nil, e.ScopesMatcher, other.ScopesMatcher)
	e.Audiences = x.IfThenElse(len(e.Audiences) != 0, e.Audiences, other.Audiences)
	e.AllowedAlgorithms = x.IfThenElse(len(e.AllowedAlgorithms) != 0, e.AllowedAlgorithms, other.AllowedAlgorithms)
	e.ValidityLeeway = x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, other.ValidityLeeway)
	e.ProofOfPossession = x.IfThenElseExec(e.ProofOfPossession != nil,
		func() PoPStrategy { return e.ProofOfPossession.Merge(other.ProofOfPossession) },
		func() PoPStrategy { return other.ProofOfPossession },
	)

	return e
}

func (e Expectation) AssertAlgorithm(token *Token) error {
	alg := token.Header.Algorithm
	if !slices.Contains(e.AllowedAlgorithms, jose.SignatureAlgorithm(alg)) {
		return NewInvalidTokenError(token.Type, "algorithm "+string(alg)+" is not allowed")
	}

	return nil
}

func (e Expectation) AssertIssuer(token *Token) error {
	if len(e.TrustedIssuers) == 0 {
		return nil
	}

	if !slices.Contains(e.TrustedIssuers, token.Claims.Issuer) {
		return NewInvalidTokenError(token.Type, "issuer "+token.Claims.Issuer+" is not trusted")
	}

	return nil
}

func (e Expectation) AssertAudience(token *Token) error {
	if len(e.Audiences) == 0 {
		return nil
	}

	if !slicex.Intersects(e.Audiences, token.Claims.Audience) {
		return NewInvalidTokenError(token.Type, "no expected audience present")
	}

	return nil
}

func (e Expectation) AssertValidity(token *Token) error {
	leeway := int64(x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway).Seconds())
	now := time.Now().Unix()
	nbf := token.Claims.NotBefore.Time().Unix()
	exp := token.Claims.Expiry.Time().Unix()

	if nbf > 0 && now+leeway < nbf {
		return NewInvalidTokenError(token.Type, "not yet valid")
	}

	if exp > 0 && now-leeway >= exp {
		return NewInvalidTokenError(token.Type, "expired")
	}

	return nil
}

func (e Expectation) AssertIssuanceTime(token *Token) error {
	leeway := x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway)
	iat := token.Claims.IssuedAt.Time()

	// IssuedAt is optional but cannot be in the future. This is not required by the RFC, but
	// if by misconfiguration it has been set to future, we don't trust it.
	if !iat.Equal(time.Time{}) && time.Now().Add(leeway).Before(iat) {
		return NewInvalidTokenError(token.Type, "issued in the future")
	}

	return nil
}

func (e Expectation) AssertScopes(token *Token) error {
	scopes := x.IfThenElse(len(token.Claims.Scp) != 0, token.Claims.Scp, token.Claims.Scope)
	if err := e.ScopesMatcher.Match(scopes); err != nil {
		var mismatch *ScopeMismatchError

		errors.As(err, &mismatch)

		return NewInsufficientScopeError(token.Type, err.Error(), mismatch.RequiredScopes())
	}

	return nil
}

func (e Expectation) AssertProofOfPossession(ctx pipeline.Context, token *Token) error {
	strategy := x.IfThenElseExec(e.ProofOfPossession != nil,
		func() PoPStrategy { return e.ProofOfPossession },
		func() PoPStrategy { return opportunisticPoPStrategy{} },
	)

	leeway := x.IfThenElse(e.ValidityLeeway != 0, e.ValidityLeeway, defaultLeeway)

	return strategy.Assert(ctx, token, leeway, e.AllowedAlgorithms)
}
