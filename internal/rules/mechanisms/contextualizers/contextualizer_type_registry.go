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

package contextualizers

import (
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedContextualizerType = errors.New("contextualizer type unsupported")

	// by intention. Used only during application bootstrap.
	typeFactories   []TypeFactory //nolint:gochecknoglobals
	typeFactoriesMu sync.RWMutex  //nolint:gochecknoglobals
)

type TypeFactory func(app app.Context, id string, typ string, c map[string]any) (bool, Contextualizer, error)

func registerTypeFactory(factory TypeFactory) {
	typeFactoriesMu.Lock()
	defer typeFactoriesMu.Unlock()

	if factory == nil {
		panic("RegisterContextualizerType factory is nil")
	}

	typeFactories = append(typeFactories, factory)
}

func CreatePrototype(app app.Context, id string, typ string, config map[string]any) (Contextualizer, error) {
	typeFactoriesMu.RLock()
	defer typeFactoriesMu.RUnlock()

	for _, create := range typeFactories {
		if ok, at, err := create(app, id, typ, config); ok {
			return at, err
		}
	}

	return nil, errorchain.NewWithMessagef(ErrUnsupportedContextualizerType, "'%s'", typ)
}
