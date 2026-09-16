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
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/pipeline"
)

type opportunisticPoPStrategy struct{}

func (s opportunisticPoPStrategy) Assert(
	ctx pipeline.Context,
	token *Token,
	leeway time.Duration,
	allowedAlgorithms []jose.SignatureAlgorithm,
) error {
	cnf := token.Claims.Confirmation
	if cnf == nil {
		return nil
	}

	if len(cnf.JWKThumbprint) != 0 {
		return (&DPoPStrategy{}).Assert(ctx, token, leeway, allowedAlgorithms)
	}

	if len(cnf.CertificateThumbprintSHA256) != 0 {
		return (&mtlsPoPStrategy{}).Assert(ctx, token, leeway, allowedAlgorithms)
	}

	return nil
}

func (s opportunisticPoPStrategy) Merge(other PoPStrategy) PoPStrategy {
	if other == nil {
		return s
	}

	return other
}
