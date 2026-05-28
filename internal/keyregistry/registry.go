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
	"maps"
	"slices"
	"sync"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/keymaterial/joseadapter"
	"github.com/dadrus/heimdall/internal/secrets"
)

type registry struct {
	mut sync.RWMutex

	// Internal keys used to calculate the snapshot
	keys map[string]secrets.AsymmetricKeySecret

	// Immutable snapshot returned by Keys().
	snapshot []jose.JSONWebKey
}

func newRegistry() (Registry, error) {
	reg := &registry{
		keys: make(map[string]secrets.AsymmetricKeySecret, 10),
	}

	return reg, nil
}

func (r *registry) Keys() []jose.JSONWebKey {
	r.mut.RLock()
	keys := r.snapshot
	r.mut.RUnlock()

	return keys
}

func (r *registry) Notify(secret secrets.AsymmetricKeySecret) {
	r.mut.Lock()
	defer r.mut.Unlock()

	r.keys[secret.KeyID()] = secret

	r.rebuildSnapshot()
}

func (r *registry) rebuildSnapshot() {
	snapshot := make([]jose.JSONWebKey, 0, len(r.keys))

	keyIDs := slices.Collect(maps.Keys(r.keys))
	slices.Sort(keyIDs)

	for _, keyID := range keyIDs {
		jwk, err := joseadapter.ToJWK(r.keys[keyID])
		if err != nil {
			continue
		}

		snapshot = append(snapshot, jwk)
	}

	r.snapshot = snapshot
}
