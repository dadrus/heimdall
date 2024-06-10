// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package cache

import (
	"errors"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"sync"

	"github.com/dadrus/heimdall/internal/cache/noop"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrUnsupportedCacheType = errors.New("cache type unsupported")

	// by intention. Used only during application bootstrap.
	factories   = make(map[string]Factory) //nolint:gochecknoglobals
	factoriesMu sync.RWMutex               //nolint:gochecknoglobals
)

func Register(typ string, factory Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()

	if factory == nil {
		panic("cache factory is nil")
	}

	factories[typ] = factory
}

func Create(typ string, config map[string]any, cw watcher.Watcher, co certificate.Observer) (Cache, error) {
	if typ == "noop" {
		return &noop.Cache{}, nil
	}

	factoriesMu.RLock()
	factory, ok := factories[typ]
	factoriesMu.RUnlock()

	if !ok {
		return nil, errorchain.NewWithMessagef(ErrUnsupportedCacheType, "'%s'", typ)
	}

	return factory.Create(config, cw, co)
}
