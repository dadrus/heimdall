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
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/keymaterial/joseadapter"
	"github.com/dadrus/heimdall/internal/secrets"
)

const publicationTimeout = 15 * time.Second

type registry struct {
	mut sync.RWMutex

	logger zerolog.Logger
	srf    secrets.ScopedResolverFactory

	// Internal key sets used to calculate the snapshot.
	//
	// Each entry represents the complete verification key set for one
	// publication reference. The outer map key is derived from the parent
	// secret reference used for key publication.
	sets map[string]map[string]secrets.AsymmetricKeySecret

	// Immutable snapshot returned by Keys().
	snapshot []jose.JSONWebKey
}

func newRegistry(
	logger zerolog.Logger,
	srf secrets.ScopedResolverFactory,
) (Registry, error) {
	reg := &registry{
		logger: logger,
		srf:    srf,
		sets:   make(map[string]map[string]secrets.AsymmetricKeySecret, 10),
	}

	return reg, nil
}

func (r *registry) Keys() []jose.JSONWebKey {
	r.mut.RLock()
	keys := r.snapshot
	r.mut.RUnlock()

	return keys
}

func (r *registry) Notify(ref secrets.Reference) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), publicationTimeout)
		defer cancel()

		r.doNotify(ctx, ref)
	}()
}

func (r *registry) doNotify(ctx context.Context, ref secrets.Reference) {
	parent := ref.Parent()
	id := publicationID(parent)

	scope := r.srf.Create(id)
	defer scope.Release()

	handle, err := scope.SecretSet(ctx, parent)
	if err != nil {
		r.logger.Warn().
			Err(err).
			Str("_source", parent.Source).
			Str("_selector", parent.Selector).
			Msg("Failed creating verification key set handle")

		return
	}

	if err = scope.AwaitReady(ctx); err != nil {
		r.logger.Warn().
			Err(err).
			Str("_source", parent.Source).
			Str("_selector", parent.Selector).
			Msg("Failed resolving verification key set")

		return
	}

	secretSet, ok := handle.Get()
	if !ok {
		r.logger.Warn().
			Str("_source", parent.Source).
			Str("_selector", parent.Selector).
			Msg("Verification key set is not available after readiness")

		return
	}

	keys := make([]secrets.AsymmetricKeySecret, 0, len(secretSet))
	for _, secret := range secretSet {
		key, ok := secret.(secrets.AsymmetricKeySecret)
		if !ok {
			r.logger.Warn().
				Str("_source", parent.Source).
				Str("_selector", parent.Selector).
				Str("_secret_selector", secret.Selector()).
				Str("_secret_kind", string(secret.Kind())).
				Msg("Ignoring non-asymmetric key secret in verification key set")

			continue
		}

		keys = append(keys, key)
	}

	r.replaceSet(id, keys)
}

func (r *registry) replaceSet(id string, keys []secrets.AsymmetricKeySecret) {
	r.mut.Lock()
	defer r.mut.Unlock()

	if len(keys) == 0 {
		delete(r.sets, id)
		r.rebuildSnapshot()

		return
	}

	set := make(map[string]secrets.AsymmetricKeySecret, len(keys))
	for _, key := range keys {
		set[key.KeyID()] = key
	}

	r.sets[id] = set
	r.rebuildSnapshot()
}

func (r *registry) rebuildSnapshot() {
	keys := make(map[string]secrets.AsymmetricKeySecret)

	for _, set := range r.sets {
		maps.Copy(keys, set)
	}

	keyIDs := slices.Collect(maps.Keys(keys))
	slices.Sort(keyIDs)

	snapshot := make([]jose.JSONWebKey, 0, len(keyIDs))

	for _, keyID := range keyIDs {
		jwk, err := joseadapter.ToJWK(keys[keyID])
		if err != nil {
			r.logger.Warn().
				Err(err).
				Str("_kid", keyID).
				Msg("Failed converting verification key to JWK")

			continue
		}

		snapshot = append(snapshot, jwk)
	}

	r.snapshot = snapshot
}

func publicationID(ref secrets.Reference) string {
	return ref.Source + ":" + ref.Selector
}
