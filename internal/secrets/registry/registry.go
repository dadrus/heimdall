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

package registry

import (
	"sync"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	// by intention. Used only during application bootstrap.
	factories   = make(map[string]Factory) //nolint:gochecknoglobals
	factoriesMu sync.RWMutex               //nolint:gochecknoglobals
)

func Register(typ string, factory Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()

	if factory == nil {
		panic("secret provider factory is nil")
	}

	factories[typ] = factory
}

func Create(app app.Context, typ, sourceName string, conf map[string]any) (types.Provider, error) {
	factoriesMu.RLock()
	factory, ok := factories[typ] //nolint:wsl_v5
	factoriesMu.RUnlock()         //nolint:wsl_v5

	if !ok {
		return nil, errorchain.NewWithMessagef(types.ErrUnsupportedProviderType, "'%s'", typ)
	}

	return factory.Create(app, sourceName, conf)
}
