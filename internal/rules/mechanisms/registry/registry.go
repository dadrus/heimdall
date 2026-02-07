// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package registry

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedMechanismType = errors.New("mechanism type unsupported")

	// by intention. Used only during application bootstrap.
	factories   = make(map[types.Kind]map[string]Factory) //nolint:gochecknoglobals
	factoriesMu sync.RWMutex                              //nolint:gochecknoglobals
)

type Factory interface {
	Create(app app.Context, name string, config map[string]any) (types.Mechanism, error)
}

type FactoryFunc func(app app.Context, name string, conf map[string]any) (types.Mechanism, error)

func (f FactoryFunc) Create(app app.Context, name string, conf map[string]any) (types.Mechanism, error) {
	return f(app, name, conf)
}

func Register(kind types.Kind, typ string, factory Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()

	kindFactories, known := factories[kind]
	if !known {
		kindFactories = make(map[string]Factory)
		factories[kind] = kindFactories
	}

	kindFactories[typ] = factory
}

func Create(app app.Context, kind types.Kind, typ, name string, config map[string]any) (types.Mechanism, error) {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()

	kindFactories, present := factories[kind]
	if !present {
		return nil, errorchain.NewWithMessagef(ErrUnsupportedMechanismType, "%s", typ)
	}

	typFactory := kindFactories[typ]
	if typFactory == nil {
		return nil, errorchain.NewWithMessagef(ErrUnsupportedMechanismType, "%s %s", typ, kind)
	}

	return typFactory.Create(app, name, config)
}
