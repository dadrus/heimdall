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

package unifiers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedUnifierType = errors.New("unifier type unsupported")

	// by intention. Used only during application bootstrap
	// nolint
	typeFactories []UnifierTypeFactory
	// nolint
	typeFactoriesMu sync.RWMutex
)

type UnifierTypeFactory func(id string, typ string, c map[string]any) (bool, Unifier, error)

func registerUnifierTypeFactory(factory UnifierTypeFactory) {
	typeFactoriesMu.Lock()
	defer typeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterUnifierType factory is nil")
	}

	typeFactories = append(typeFactories, factory)
}

func CreateUnifierPrototype(id string, typ string, mConfig map[string]any) (Unifier, error) {
	typeFactoriesMu.RLock()
	defer typeFactoriesMu.RUnlock()

	for _, create := range typeFactories {
		if ok, at, err := create(id, typ, mConfig); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedUnifierType, "'%s'", typ)
}
