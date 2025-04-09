// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package keyholder

import "github.com/go-jose/go-jose/v4"

type KeyHolder interface {
	Keys() []jose.JSONWebKey
}

//go:generate mockery --name Registry --structname RegistryMock

type Registry interface {
	AddKeyHolder(kh KeyHolder)
	Keys() []jose.JSONWebKey
}

func newRegistry() Registry {
	return &registry{}
}

type registry struct {
	keyHolders []KeyHolder
}

func (r *registry) AddKeyHolder(kh KeyHolder) {
	r.keyHolders = append(r.keyHolders, kh)
}

func (r *registry) Keys() []jose.JSONWebKey {
	var keys []jose.JSONWebKey

	for _, holder := range r.keyHolders {
		keys = append(keys, holder.Keys()...)
	}

	return keys
}
