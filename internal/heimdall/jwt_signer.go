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

package heimdall

import (
	"time"

	"github.com/go-jose/go-jose/v3"
)

//go:generate mockery --name JWTSigner --structname JWTSignerMock

type JWTSigner interface {
	Sign(sub string, ttl time.Duration, claims map[string]any) (string, error)
	Hash() []byte
	Keys() []jose.JSONWebKey
}
