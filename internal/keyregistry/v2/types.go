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

package keyregistry

import (
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/go-jose/go-jose/v4"
)

type KeyObserver interface {
	Notify(ki KeyInfo)
}

type JWKSProvider interface {
	Keys() []jose.JSONWebKey
}

type KeyInfo struct {
	Key secrets.AsymmetricKeySecret
	Exportable bool
}

type Registry interface {
	KeyObserver
	JWKSProvider
}
