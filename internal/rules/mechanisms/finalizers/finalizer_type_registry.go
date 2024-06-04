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

package finalizers

import (
	"errors"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/watcher"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedType = errors.New("finalizer type unsupported")

	// by intention. Used only during application bootstrap.
	typeFactories   []TypeFactory //nolint:gochecknoglobals
	typeFactoriesMu sync.RWMutex  //nolint:gochecknoglobals
)

//go:generate mockery --name CreationContext --structname CreationContextMock  --inpackage --testonly

type CreationContext interface {
	Watcher() watcher.Watcher
	KeyHolderRegistry() keyholder.Registry
}

type TypeFactory func(ctx CreationContext, id string, typ string, c map[string]any) (bool, Finalizer, error)

func registerTypeFactory(factory TypeFactory) {
	typeFactoriesMu.Lock()
	defer typeFactoriesMu.Unlock()

	if factory == nil {
		panic("finalizer type factory is nil")
	}

	typeFactories = append(typeFactories, factory)
}

func CreatePrototype(ctx CreationContext, id string, typ string, mConfig map[string]any) (Finalizer, error) {
	typeFactoriesMu.RLock()
	defer typeFactoriesMu.RUnlock()

	for _, create := range typeFactories {
		if ok, at, err := create(ctx, id, typ, mConfig); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedType, "'%s'", typ)
}
